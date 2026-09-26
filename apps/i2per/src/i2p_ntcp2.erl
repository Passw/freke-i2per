-module(i2p_ntcp2).

-moduledoc """
NTCP2 Noise XK handshake (`Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`).

Pure state-passing implementation of the three-message NTCP2 key agreement
(I2P [NTCP2](https://i2p.net/en/docs/specs/ntcp2/) spec, "Handshake" section)
that runs before the data phase (`m:i2p_framing`). Every step is a pure
function from a `t:state/0` (and the step's inputs) to the next state; the
connection process drives one side per connection.

Wire format of the three messages:

```
msg1 Alice -> Bob  : AES-CBC(X) || ChaChaPoly(options, k1, n=0) || padding
msg2 Bob -> Alice  : AES-CBC(Y) || ChaChaPoly(options, k2, n=0) || padding
msg3 Alice -> Bob  : ChaChaPoly(S, k2, n=1) || ChaChaPoly(payload, k3, n=0)
```

Where `X`/`Y` are the AES-256-CBC-obfuscated X25519 ephemeral keys (the Noise
`aesobfse` modifier, key = Bob's router hash, IV = Bob's published IV and
chained across the X||Y stream), `S` is Alice's static key, and the msg3
payload is Alice's RouterInfo with `m3p2len` (announced in msg1) being the
length of its AEAD frame.

The Noise state advances as:

```
ck = SHA256(protocol_name)
h  = SHA256(ck), then h = SHA256(h || rs)     %% rs = responder static key
msg1: h = SHA256(h || X);  k1 = MixKey(DH(es));       AEAD(options, k1, n=0)
      h = SHA256(h || frame); h = SHA256(h || padding)
msg2: h = SHA256(h || Y);  k2 = MixKey(DH(ee));       AEAD(options, k2, n=0)
      h = SHA256(h || frame); h = SHA256(h || padding)
msg3: AEAD(S, k2, n=1); h = SHA256(h || frame)
      k3 = MixKey(DH(se)); AEAD(payload, k3, n=0); h = SHA256(h || frame)
```

Nonces are the Noise nonce (4 zero bytes || 8-byte little-endian counter), see
`i2p_crypto:es_nonce/1`. The final `{ck, h}` feed
`i2p_framing:data_phase_keys/2`.

These functions may return the atom `error` for protocol violations (malformed
frames, all-zero X25519 DH results, version/network-ID mismatches, padding
length mismatch); the caller decides how the connection ends (the connection
process treats any `error` as a fatal handshake failure).

## Usage

```erlang
%% Alice, initiating to Bob's RouterInfo: rs = Bob's static key,
%% BobHash = Bob's router hash, BobIV = iv from Bob's NTCP2 address.
S0 = i2p_ntcp2:alice_init(Rs, BobHash, BobIV, MyStaticPriv, MyStaticPub),
{EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
Opts = #{padlen => 0, m3p2len => byte_size(Payload) + 16, ts => Now},
{ok, Msg1, S1} = i2p_ntcp2:create_msg1(S0, EphPriv, Opts, <<>>),

%% Bob receives msg1 and answers msg2.
{ok, #{padlen := PadLen}, S2} = i2p_ntcp2:receive_msg1(BobS0, Msg1),
{ok, Msg2, S3} = i2p_ntcp2:create_msg2(S2, BobEphPriv, Pad, TsB),

%% Alice completes with msg3, both sides derive the data-phase keys.
{ok, Msg3, S4} = i2p_ntcp2:create_msg3(S1, Payload),
{ok, Payload, S5} = i2p_ntcp2:receive_msg3(S3, Msg3),
KeysA = i2p_ntcp2:data_phase_keys(S4),
KeysB = i2p_ntcp2:data_phase_keys(S5),
```
""".

%%% --------------------------------------------------------------------------
%%% API
%%% --------------------------------------------------------------------------

-export([
    initialize/1,
    alice_init/5,
    create_msg1/4,
    receive_msg2/2,
    create_msg3/2,
    bob_init/4,
    receive_msg1/2,
    create_msg2/4,
    receive_msg3/2,
    data_phase_keys/1,
    receive_msg1_stream/2,
    receive_msg2_stream/2,
    receive_msg3_stream/2
]).
-export_type([
    state/0,
    options1/0,
    options2/0,
    recv_fun/0
]).

-define(PROTOCOL_NAME, <<"Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256">>).
-define(NET_ID, 2).
-define(VERSION, 2).

-doc """
Alice's msg1 options: padding length (`padlen`, must equal the actual padding),
the msg3 part 2 AEAD frame length (`m3p2len`, including its 16-byte MAC), and
Alice's Unix timestamp `ts`. The network ID (2) and protocol version (2) are
constants.
""".
-type options1() :: #{
    padlen := non_neg_integer(),
    m3p2len := pos_integer(),
    ts := non_neg_integer()
}.

-doc "Bob's msg2 options: padding length and timestamp.".
-type options2() :: #{
    padlen := non_neg_integer(),
    ts := non_neg_integer()
}.

-doc """
A byte source for the stream handshake readers: given a byte count, return
exactly that many bytes or `error`. The connection process supplies one backed
by `gen_tcp:recv/3`; tests can supply a split binary to exercise
fragmentation.
""".
-type recv_fun() :: fun((non_neg_integer()) -> {ok, binary()} | error).

-doc """
The handshake state threaded through the step functions.

Both sides share one schema. `eph_priv` and `re` are `undefined` until the step
that produces them has run (`eph_priv` from `create_msg1/4`/`create_msg2/4`, `re`
once the remote ephemeral key is known). `rs` is always the responder's (Bob's)
static public key; `remote_hash` and `iv` are Bob's router hash and published IV
(the msg2 IV chains from the msg1 ciphertext). `m3p2len` is Alice's announced
msg3 part 2 frame length.
""".
-type state() :: #{
    ck := i2p_crypto:chaining_key(),
    h := i2p_crypto:hash(),
    k := i2p_crypto:key(),
    n := non_neg_integer(),
    rs := i2p_crypto:x25519_public_key(),
    my_priv := i2p_crypto:x25519_private_key(),
    my_pub := i2p_crypto:x25519_public_key(),
    eph_priv := i2p_crypto:x25519_private_key() | undefined,
    re := i2p_crypto:x25519_public_key() | undefined,
    remote_hash := i2p_crypto:hash(),
    iv := i2p_crypto:aes_iv(),
    m3p2len := non_neg_integer()
}.

-doc """
Precompute the Noise initialization common to both sides (before the `e` step).

`ck = SHA256(protocol_name)`, then the null prologue MixHash folds in a second
`SHA256(protocol_name)` before MixHash-ing the responder static key, so
`h = SHA256(SHA256(SHA256(protocol_name)) || rs)`. The double hash matches the
Noise XK init as used by the reference implementation (i2pd's
`InitNoiseXKState`). Identical for Alice (with Bob's static key) and Bob (with
his own), and precomputable for all connections.

Input: `Rs` — the responder's (Bob's) 32-byte X25519 static public key.
Output: `{Ck, H}` — the chaining key and hash.
""".
-spec initialize(i2p_crypto:x25519_public_key()) ->
    {i2p_crypto:chaining_key(), i2p_crypto:hash()}.
initialize(Rs) ->
    Ck = crypto:hash(sha256, ?PROTOCOL_NAME),
    {Ck, i2p_crypto:mixhash(crypto:hash(sha256, Ck), Rs)}.

-doc """
Alice's initial handshake state for a connection to Bob.

Input: `Rs` — Bob's static public key; `BobHash` — Bob's router hash (SHA-256
of his RouterIdentity, the AES-CBC key for X and Y); `BobIV` — the IV published
in Bob's NTCP2 address; `MyStaticPriv`/`MyStaticPub` — Alice's own static
keypair (the `se` DH in msg3).
Output: the initial `t:state/0`.
""".
-spec alice_init(
    i2p_crypto:x25519_public_key(),
    i2p_crypto:hash(),
    i2p_crypto:aes_iv(),
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key()
) -> state().
alice_init(Rs, BobHash, BobIV, MyStaticPriv, MyStaticPub) ->
    {Ck, H} = initialize(Rs),
    #{
        ck => Ck,
        h => H,
        k => <<0:256>>,
        n => 0,
        rs => Rs,
        my_priv => MyStaticPriv,
        my_pub => MyStaticPub,
        eph_priv => undefined,
        re => undefined,
        remote_hash => BobHash,
        iv => BobIV,
        m3p2len => 0
    }.

-doc """
Alice sends message 1: the AES-obfuscated ephemeral key, options and padding.

Input: `State` — from `alice_init/5`; `EphPriv` — a fresh X25519 ephemeral
private key; `Options` — msg1 options (`t:options1/0`); `Pad` — random padding
(0 or more bytes, mixed into `h`). `Options.padlen` must equal
`byte_size(Pad)`.
Output: `{ok, Msg1, State'}` where `Msg1` is
`AES-CBC(X) || ChaChaPoly(options) || padding`, or the atom `error` on an
all-zero `es` DH result.
""".
-spec create_msg1(state(), i2p_crypto:x25519_private_key(), options1(), binary()) ->
    {ok, binary(), state()} | error.
create_msg1(State, EphPriv, Options, Pad) ->
    #{ck := Ck, h := H, rs := Rs, remote_hash := RemoteHash, iv := Iv} = State,
    X = clear_highest_bit(i2p_crypto:x25519_public_key(EphPriv)),
    AesX = i2p_crypto:aes256cbc_encrypt(RemoteHash, Iv, X),
    ChainedIv = last_block(AesX),
    H1 = i2p_crypto:mixhash(H, X),
    case dh(EphPriv, Rs) of
        {ok, Es} ->
            {Ck1, K1} = i2p_crypto:mixkey(Ck, Es),
            Frame = seal(K1, 0, options1_encode(Options), H1),
            H2 = i2p_crypto:mixhash(H1, Frame),
            H3 = i2p_crypto:mixhash(H2, Pad),
            State1 = State#{
                ck => Ck1,
                h => H3,
                k => K1,
                n => 1,
                eph_priv => EphPriv,
                iv => ChainedIv,
                m3p2len => maps:get(m3p2len, Options)
            },
            {ok, <<AesX/binary, Frame/binary, Pad/binary>>, State1};
        error ->
            error
    end.

-doc """
Alice processes Bob's message 2.

Input: `State` — from `create_msg1/4`; `Msg2` —
`AES-CBC(Y) || ChaChaPoly(options) || padding`.
Output: `{ok, Options, State'}` — Bob's parsed `t:options2/0` and the advanced
state (Bob's ephemeral `Y` stored as `re`, cipher key `k2`), or the atom
`error` on any failure (AES/deobfuscation, AEAD authentication, padding length,
all-zero `ee` DH).
""".
-spec receive_msg2(state(), binary()) -> {ok, options2(), state()} | error.
receive_msg2(State, <<AesY:32/binary, Frame:32/binary, Pad/binary>>) ->
    case msg2_open(State, AesY, Frame) of
        {ok, Cont} -> msg2_finish(Cont, Pad);
        error -> error
    end;
receive_msg2(_State, _Msg2) ->
    error.

-doc """
Alice processes Bob's message 2 as it arrives over a stream.

Identical to `receive_msg2/2` but reads from a `t:recv_fun/0` byte source: the
32-byte AES-obfuscated ephemeral key, the 32-byte options frame, then the
padding (length from the decrypted options). Output: `{ok, Options, State'}`
or the atom `error`.
""".
-spec receive_msg2_stream(state(), recv_fun()) -> {ok, options2(), state()} | error.
receive_msg2_stream(State, Recv) ->
    maybe
        {ok, AesY} ?= Recv(32),
        {ok, Frame} ?= Recv(32),
        {ok, Cont} ?= msg2_open(State, AesY, Frame),
        #{opts := #{padlen := PadLen}} = Cont,
        {ok, Pad} ?= Recv(PadLen),
        msg2_finish(Cont, Pad)
    else
        error -> error
    end.

%% Shared msg2 parse, stage 1: decrypt Y (AES-CBC), DH against our own
%% ephemeral key, and open the options frame. Returns Bob's parsed options and
%% the intermediate handshake values consumed by msg2_finish/2; used by both
%% receive_msg2/2 and the stream reader.
msg2_open(State, AesY, Frame) ->
    #{ck := Ck, h := H, eph_priv := EphPriv, remote_hash := RemoteHash, iv := Iv} =
        State,
    Y = i2p_crypto:aes256cbc_decrypt(RemoteHash, Iv, AesY),
    H1 = i2p_crypto:mixhash(H, Y),
    case dh(EphPriv, Y) of
        {ok, Ee} ->
            {Ck1, K1} = i2p_crypto:mixkey(Ck, Ee),
            case open(K1, 0, Frame, H1) of
                {ok, <<_:16, PadLen:16/big, _:32, Ts:32/big, _:32>>} ->
                    {ok, #{
                        opts => #{padlen => PadLen, ts => Ts},
                        h => i2p_crypto:mixhash(H1, Frame),
                        ck => Ck1,
                        k => K1,
                        re => Y,
                        state => State
                    }};
                _ ->
                    error
            end;
        error ->
            error
    end.

%% Shared msg2 parse, stage 2: fold the padding into the hash and advance the
%% handshake state once the whole message has arrived.
msg2_finish(Cont, Pad) ->
    #{
        opts := #{padlen := PadLen} = Opts,
        h := H2,
        ck := Ck1,
        k := K1,
        re := Y,
        state := State
    } =
        Cont,
    case byte_size(Pad) =:= PadLen of
        true ->
            H3 = i2p_crypto:mixhash(H2, Pad),
            {ok, Opts, State#{
                ck => Ck1,
                h => H3,
                k => K1,
                n => 1,
                re => Y
            }};
        false ->
            error
    end.

-doc """
Alice sends message 3: her encrypted static key (n=1) and the RouterInfo payload
(n=0).

Input: `State` — from `receive_msg2/2`; `Payload` — Alice's msg3 part 2
plaintext (RouterInfo block, options and padding), whose AEAD frame must be
exactly `m3p2len` bytes (`byte_size(Payload) = m3p2len - 16`).
Output: `{ok, Msg3, State'}` where `Msg3` is
`ChaChaPoly(S) || ChaChaPoly(payload)`, or the atom `error` on an all-zero `se`
DH result or a payload length mismatch.
""".
-spec create_msg3(state(), binary()) -> {ok, binary(), state()} | error.
create_msg3(State, Payload) ->
    #{ck := Ck, h := H, k := K, n := N, re := Re, my_priv := MyPriv, m3p2len := M3P2Len} =
        State,
    case byte_size(Payload) + 16 of
        M3P2Len ->
            Part1 = seal(K, N, my_pub(State), H),
            H1 = i2p_crypto:mixhash(H, Part1),
            case dh(MyPriv, Re) of
                {ok, Se} ->
                    {Ck1, K1} = i2p_crypto:mixkey(Ck, Se),
                    Part2 = seal(K1, 0, Payload, H1),
                    H2 = i2p_crypto:mixhash(H1, Part2),
                    {ok, <<Part1/binary, Part2/binary>>, State#{
                        ck => Ck1,
                        h => H2,
                        k => K1,
                        n => 1
                    }};
                error ->
                    error
            end;
        _ ->
            error
    end.

-doc """
Bob's initial handshake state for an incoming connection.

Input: `MyStaticPriv`/`MyStaticPub` — Bob's static keypair (the `es` DH in msg1
and the `se` DH in msg3); `MyHash` — Bob's router hash (the AES-CBC key);
`MyIV` — Bob's published NTCP2 IV.
Output: the initial `t:state/0`.
""".
-spec bob_init(
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key(),
    i2p_crypto:hash(),
    i2p_crypto:aes_iv()
) -> state().
bob_init(MyStaticPriv, MyStaticPub, MyHash, MyIV) ->
    {Ck, H} = initialize(MyStaticPub),
    #{
        ck => Ck,
        h => H,
        k => <<0:256>>,
        n => 0,
        rs => MyStaticPub,
        my_priv => MyStaticPriv,
        my_pub => MyStaticPub,
        eph_priv => undefined,
        re => undefined,
        remote_hash => MyHash,
        iv => MyIV,
        m3p2len => 0
    }.

-doc """
Bob processes Alice's message 1.

Input: `State` — from `bob_init/4`; `Msg1` —
`AES-CBC(X) || ChaChaPoly(options) || padding`.
Output: `{ok, Options, State'}` — Alice's parsed `t:options1/0` (including
`m3p2len` for reading msg3) and the advanced state, or the atom `error` on any
failure (AES deobfuscation, AEAD authentication, version/network-ID mismatch,
padding length, all-zero `es` DH, or an X with the high bit set, which requests
an unsupported ML-KEM upgrade).
""".
-spec receive_msg1(state(), binary()) -> {ok, options1(), state()} | error.
receive_msg1(State, <<AesX:32/binary, Frame:32/binary, Pad/binary>>) ->
    case msg1_open(State, AesX, Frame) of
        {ok, Cont} -> msg1_finish(Cont, Pad);
        error -> error
    end;
receive_msg1(_State, _Msg1) ->
    error.

-doc """
Bob processes Alice's message 1 as it arrives over a stream.

Identical to `receive_msg1/2` but reads the message from a `t:recv_fun/0`
byte source instead of a pre-assembled binary: the 32-byte AES-obfuscated
ephemeral key, the 32-byte options frame, then the padding (its length is
learned from the decrypted options). Handles arbitrary TCP segmentation.
Output: `{ok, Options, State'}` or the atom `error`.
""".
-spec receive_msg1_stream(state(), recv_fun()) -> {ok, options1(), state()} | error.
receive_msg1_stream(State, Recv) ->
    maybe
        {ok, AesX} ?= Recv(32),
        {ok, Frame} ?= Recv(32),
        {ok, Cont} ?= msg1_open(State, AesX, Frame),
        #{opts := #{padlen := PadLen}} = Cont,
        {ok, Pad} ?= Recv(PadLen),
        msg1_finish(Cont, Pad)
    else
        error -> error
    end.

%% Shared msg1 parse, stage 1: de-obfuscate the ephemeral key (AES-CBC,
%% chaining the IV), reject an X with the ML-KEM probe bit set, DH against the
%% responder static key, and open+validate the options frame. Used by both
%% receive_msg1/2 and the stream reader; returns Alice's parsed options plus
%% the intermediate handshake values consumed by msg1_finish/2.
msg1_open(State, AesX, Frame) ->
    #{ck := Ck, h := H, my_priv := MyPriv, remote_hash := RemoteHash, iv := Iv} =
        State,
    X = i2p_crypto:aes256cbc_decrypt(RemoteHash, Iv, AesX),
    ChainedIv = last_block(AesX),
    case X of
        <<_:31/binary, B:8>> when B band 128 =:= 0 ->
            H1 = i2p_crypto:mixhash(H, X),
            case dh(MyPriv, X) of
                {ok, Es} ->
                    {Ck1, K1} = i2p_crypto:mixkey(Ck, Es),
                    case open(K1, 0, Frame, H1) of
                        {ok,
                            <<NetId:8, Ver:8, PadLen:16/big, M3P2Len:16/big, _:16, Ts:32/big,
                                _:32>>} when
                            NetId =:= ?NET_ID orelse NetId =:= 0,
                            Ver =:= ?VERSION,
                            M3P2Len >= 19
                        ->
                            {ok, #{
                                opts => #{
                                    padlen => PadLen,
                                    m3p2len => M3P2Len,
                                    ts => Ts
                                },
                                h => i2p_crypto:mixhash(H1, Frame),
                                ck => Ck1,
                                k => K1,
                                re => X,
                                iv => ChainedIv,
                                state => State
                            }};
                        _ ->
                            error
                    end;
                error ->
                    error
            end;
        _ ->
            error
    end.

%% Shared msg1 parse, stage 2: fold the padding into the hash and advance the
%% handshake state once the whole message has arrived.
msg1_finish(Cont, Pad) ->
    #{
        opts := #{padlen := PadLen} = Opts,
        h := H2,
        ck := Ck1,
        k := K1,
        re := X,
        iv := ChainedIv,
        state := State
    } =
        Cont,
    case byte_size(Pad) =:= PadLen of
        true ->
            H3 = i2p_crypto:mixhash(H2, Pad),
            {ok, Opts, State#{
                ck => Ck1,
                h => H3,
                k => K1,
                n => 1,
                re => X,
                iv => ChainedIv,
                m3p2len => maps:get(m3p2len, Opts)
            }};
        false ->
            error
    end.

-doc """
Bob sends message 2: the AES-obfuscated ephemeral key, options and padding.

Input: `State` — from `receive_msg1/2`; `EphPriv` — a fresh X25519 ephemeral
private key; `Pad` — random padding (mixed into `h`); `TsB` — Bob's timestamp.
Output: `{ok, Msg2, State'}` where `Msg2` is
`AES-CBC(Y) || ChaChaPoly(options) || padding`, or the atom `error` on an
all-zero `ee` DH result.
""".
-spec create_msg2(state(), i2p_crypto:x25519_private_key(), binary(), non_neg_integer()) ->
    {ok, binary(), state()} | error.
create_msg2(State, EphPriv, Pad, TsB) ->
    #{ck := Ck, h := H, re := Re, remote_hash := RemoteHash, iv := Iv} = State,
    Y = i2p_crypto:x25519_public_key(EphPriv),
    AesY = i2p_crypto:aes256cbc_encrypt(RemoteHash, Iv, Y),
    H1 = i2p_crypto:mixhash(H, Y),
    case dh(EphPriv, Re) of
        {ok, Ee} ->
            {Ck1, K1} = i2p_crypto:mixkey(Ck, Ee),
            PadLen = byte_size(Pad),
            Frame = seal(K1, 0, options2_encode(#{padlen => PadLen, ts => TsB}), H1),
            H2 = i2p_crypto:mixhash(H1, Frame),
            H3 = i2p_crypto:mixhash(H2, Pad),
            {ok, <<AesY/binary, Frame/binary, Pad/binary>>, State#{
                ck => Ck1,
                h => H3,
                k => K1,
                n => 1,
                eph_priv => EphPriv
            }};
        error ->
            error
    end.

-doc """
Bob processes Alice's message 3.

Input: `State` — from `create_msg2/4`; `Msg3` —
`ChaChaPoly(S) || ChaChaPoly(payload)` (48 bytes plus exactly `m3p2len`).
Output: `{ok, Payload, State'}` — Alice's decrypted msg3 payload and the
advanced state, or the atom `error` on any failure (AEAD authentication, wrong
length, all-zero `se` DH).
""".
-spec receive_msg3(state(), binary()) -> {ok, binary(), state()} | error.
receive_msg3(State, Msg3) ->
    #{ck := Ck, h := H, k := K, n := N, eph_priv := EphPriv, m3p2len := M3P2Len} =
        State,
    %% Stays a case: the Part2 segment size is M3P2Len, bound above — a head
    %% pattern cannot reference bindings from outside itself.
    case Msg3 of
        <<Part1:48/binary, Part2:M3P2Len/binary>> ->
            case open(K, N, Part1, H) of
                {ok, S} ->
                    H1 = i2p_crypto:mixhash(H, Part1),
                    case dh(EphPriv, S) of
                        {ok, Se} ->
                            {Ck1, K1} = i2p_crypto:mixkey(Ck, Se),
                            case open(K1, 0, Part2, H1) of
                                {ok, Payload} ->
                                    H2 = i2p_crypto:mixhash(H1, Part2),
                                    {ok, Payload, State#{
                                        ck => Ck1,
                                        h => H2,
                                        k => K1,
                                        n => 1,
                                        rs => S
                                    }};
                                error ->
                                    error
                            end;
                        error ->
                            error
                    end;
                error ->
                    error
            end;
        _ ->
            error
    end.

-doc """
Bob processes Alice's message 3 as it arrives over a stream.

The responder knows the payload length from the `m3p2len` option in message 1,
so this reads exactly 48 bytes (static key frame) then `m3p2len` bytes and
defers to `receive_msg3/2`. Output: `{ok, Payload, State'}` or the atom
`error`.
""".
-spec receive_msg3_stream(state(), recv_fun()) -> {ok, binary(), state()} | error.
receive_msg3_stream(State, Recv) ->
    #{m3p2len := M3P2Len} = State,
    case Recv(48) of
        {ok, Part1} ->
            case Recv(M3P2Len) of
                {ok, Part2} -> receive_msg3(State, <<Part1/binary, Part2/binary>>);
                error -> error
            end;
        error ->
            error
    end.

-doc """
Derive the data-phase keys from the completed handshake.

Input: `State` — the final state after `create_msg3/2` (Alice) or
`receive_msg3/2` (Bob).
Output: the `t:i2p_framing:direction_keys/0` map from
`i2p_framing:data_phase_keys/2`.
""".
-spec data_phase_keys(state()) -> i2p_framing:direction_keys().
data_phase_keys(#{ck := Ck, h := H}) ->
    i2p_framing:data_phase_keys(Ck, H).

%%%%%%%
%%% Internal
%%%%%%%

options1_encode(#{padlen := PadLen, m3p2len := M3P2Len, ts := Ts}) ->
    <<?NET_ID:8, ?VERSION:8, PadLen:16/big, M3P2Len:16/big, 0:16, Ts:32/big, 0:32>>.

options2_encode(#{padlen := PadLen, ts := Ts}) ->
    <<0:16, PadLen:16/big, 0:32, Ts:32/big, 0:32>>.

%% X25519 shared secret, rejecting the all-zero result of a small-order key.
dh(Priv, Pub) ->
    case i2p_crypto:x25519_dh(Priv, Pub) of
        <<0:256>> -> error;
        Secret -> {ok, Secret}
    end.

seal(Key, N, Data, H) ->
    i2p_crypto:chacha20_poly1305_seal(Key, i2p_crypto:es_nonce(N), Data, H).

open(Key, N, Data, H) ->
    i2p_crypto:chacha20_poly1305_open(Key, i2p_crypto:es_nonce(N), Data, H).

%% Our static public key: Alice's own; on the Bob side equals rs.
my_pub(#{my_pub := Pub}) ->
    Pub.

%% The last ciphertext block becomes the IV for the next AES-CBC segment.
last_block(Bin) ->
    LastSize = byte_size(Bin) - 16,
    <<_:LastSize/binary, Last:16/binary>> = Bin,
    Last.

%% A high bit on the final byte of the ephemeral public key requests the
%% ML-KEM handshake (RFC 7748 ignores the bit in the DH, so clearing it is
%% free). A peer that sees it set treats the message as PQ and we reject that.
clear_highest_bit(<<Pref:31/binary, B:8>>) ->
    <<Pref/binary, (B band 127)>>.
