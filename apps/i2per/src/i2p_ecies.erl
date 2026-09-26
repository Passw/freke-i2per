-module(i2p_ecies).

-moduledoc """
ECIES tunnel build record encryption and key derivation.

Implements the cryptographic operations for ECIES-X25519 tunnel creation
(ShortTunnelBuild type 25 / OTBRM type 26), per the
[tunnel-creation-ecies spec](https://geti2p.net/en/docs/specs/tunnel-creation-ecies).

Every build request record is encrypted independently: each side starts from
a fresh `m:i2p_crypto:noise_n_initialize/0` state and folds in the target
hop's full static X25519 public key via MixHash before the record-specific
ephemeral exchange. A hop locates its own record by matching the 16-byte
truncated identity hash prefix — no position knowledge required.

This module provides:

- Build request record encryption/decryption using the Noise N pattern
  (`Noise_N_25519_ChaChaPoly_SHA256`), one independent Noise session per
  record.
- Reply/layer KDF derivation: `SMTunnelReplyKey`, `SMTunnelLayerKey`,
  `TunnelLayerIVKey`.
- OBEP reply record encryption/decryption (ChaCha20-Poly1305 AEAD).
- Iterative ChaCha20 reply layering (hops) and peeling (creator).

Everything here is stateless; the tunnel build state machine lives in
`m:i2p_tunnel`.

## Usage

```erlang
%% Encrypt build request records for a 3-hop outbound tunnel
Hops = [#{eph_priv => EP, hop_pub => HP, id_hash => IH} || ...],
{Records, Keys} = i2p_ecies:encrypt_build_records(Hops, Plaintexts, ObepPos),

%% A hop finds and decrypts its own record
{ok, Index} = i2p_ecies:find_own_record(OurIdHash, Records),
EncRecord = lists:nth(Index + 1, Records),
{ok, Plaintext, Hf, Ck1} =
    i2p_ecies:decrypt_build_request_record(StaticPriv, OurFullPub, EncRecord),

%% Derive reply/layer keys from the chaining key
#{reply_key := RKey, layer_key := LKey, iv_key := IVKey} =
    i2p_ecies:derive_reply_layer_keys(Ck1),

%% OBEP seals its reply record; other slots are layered with ChaCha20
Enc = i2p_ecies:encrypt_reply_record(ReplyKey, ReplyPlaintext, Hf, Position),
Layered = i2p_ecies:encrypt_reply_layer(ReplyKey, Record, SlotPosition)
```
""".

-export([
    truncated_identity_hash/1,
    encrypt_build_record/5,
    decrypt_build_request_record/3,
    encrypt_build_records/3,
    find_own_record/2,
    derive_reply_layer_keys/1,
    derive_obep_keys/1,
    decrypt_reply_record/4,
    decrypt_reply_layer/3,
    encrypt_reply_record/4,
    encrypt_reply_layer/3
]).

-export_type([
    tunnel_request/0,
    noise_n_state/0,
    reply_layer_keys/0,
    hop_desc/0,
    hop_build_keys/0
]).

-doc """
A plaintext build request record (154 bytes), per the short record specification.

All fields are big-endian. The `options` binary is the raw Mapping bytes
(including the 2-byte length prefix); an empty Mapping is `<<0, 0>>`.
""".
-type tunnel_request() :: #{
    recv_tunnel_id := 0..16#FFFFFFFF,
    next_tunnel_id := 0..16#FFFFFFFF,
    next_router_hash := binary(),
    flags := byte(),
    layer_encryption_type := byte(),
    request_time_minutes => non_neg_integer(),
    request_expiration => non_neg_integer(),
    next_msg_id => non_neg_integer(),
    options => binary()
}.

-doc "The initial Noise N chaining state `{Hash, ChainingKey}` from `m:i2p_crypto:noise_n_initialize/0`.".
-type noise_n_state() :: {i2p_crypto:hash(), i2p_crypto:chaining_key()}.

-doc """
Reply/layer keys derived from the chaining key after build request record
encryption/decryption, via `derive_reply_layer_keys/1`.

All three keys are32-byte ChaCha20 keys.
""".
-type reply_layer_keys() :: #{
    reply_key := i2p_crypto:key(),
    layer_key := i2p_crypto:key(),
    iv_key := i2p_crypto:key(),
    %% Only set for OBEP-role records: the ExistingSession (RGarlic) key and
    %% 8-byte tag with which the outbound build reply is garlic-wrapped.
    rgarlic_key := i2p_crypto:key() | undefined,
    rgarlic_tag => binary() | undefined
}.

-doc """
One build-request target hop: the creator's fresh ephemeral private key
(unique per hop and per build), the hop's static X25519 public key from its
RouterIdentity, and the hop's full 32-byte RouterIdentity hash whose first16
bytes address the record.
""".
-type hop_desc() :: #{
    eph_priv := i2p_crypto:x25519_private_key(),
    hop_pub := i2p_crypto:x25519_public_key(),
    id_hash := i2p_crypto:hash()
}.

-doc """
Creator-side per-hop material retained after building the records: the keys
needed to open this hop's reply record when the OTBRM returns, plus the final
Noise hash (the AEAD associated data of this hop's reply record).
""".
-type hop_build_keys() :: #{
    reply_key := i2p_crypto:key(),
    layer_key := i2p_crypto:key(),
    iv_key := i2p_crypto:key(),
    noise_h := i2p_crypto:hash(),
    %% OBEP-position hops only: ExistingSession (RGarlic) wrap material for
    %% the outbound build reply this hop will assemble and send back.
    rgarlic_key => i2p_crypto:key() | undefined,
    rgarlic_tag => binary() | undefined
}.

%%%%%%% %%% Internal %%%%%%%
-define(BUILD_REQUEST_PLAINTEXT_SIZE, 154).
-define(REPLY_PLAINTEXT_SIZE, 202).
-define(TRUNCATED_HASH_SIZE, 16).
-define(RECORD_SIZE, ?TRUNCATED_HASH_SIZE + 32 + ?BUILD_REQUEST_PLAINTEXT_SIZE + 16).

-doc """
SHA-256 truncated to 16 bytes — the hop identifier written at the start of
each encrypted build request record.

Input: `IdentityHash` — the full 32-byte SHA-256 of the RouterIdentity.
Output: the first16 bytes.
""".
-spec truncated_identity_hash(i2p_crypto:hash()) -> binary().
truncated_identity_hash(<<Prefix:?TRUNCATED_HASH_SIZE/binary, _/binary>>) ->
    Prefix.

%%%%%%% %%% Build Request Record Encryption %%%%%%%

-doc """
Encrypt one build request record using the Noise N pattern.

Each record is an independent Noise N session: start from a fresh
`m:i2p_crypto:noise_n_initialize/0` state; this function first MixHashes the
hop's full static X25519 public key into the chaining hash, then performs the
ephemeral exchange. The record is addressed to the hop by the first16 bytes
of its RouterIdentity hash.

Input: `EphPriv` — fresh 32-byte ephemeral X25519 private key (MUST be unique
per hop and per build); `HopPub` — the hop's static 32-byte X25519 public key
(from its RouterIdentity); `HopIdHash` — the hop's full 32-byte RouterIdentity
hash; `{H0, Ck0}` — a fresh initial Noise N state; `Plaintext` — the 154-byte
build request record.
Output: `{EncRecord, H', Ck'}` where `EncRecord` is218 bytes (truncated
identity hash ‖ ephemeral key ‖ ciphertext ‖ tag) and `H'` is the final Noise
hash (the reply record's AEAD associated data) and `Ck'` the post-handshake
chaining key (input to the reply/layer KDFs).
""".
-spec encrypt_build_record(
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key(),
    i2p_crypto:hash(),
    noise_n_state(),
    binary()
) -> {binary(), i2p_crypto:hash(), i2p_crypto:chaining_key()}.
encrypt_build_record(EphPriv, HopPub, HopIdHash, {H0, Ck0}, Plaintext) when
    byte_size(Plaintext) =:= ?BUILD_REQUEST_PLAINTEXT_SIZE
->
    H1 = i2p_crypto:mixhash(H0, HopPub),
    {CT, Tag, H2, Ck1} = i2p_crypto:noise_n_encrypt(EphPriv, HopPub, H1, Ck0, Plaintext),
    HopTrunc = truncated_identity_hash(HopIdHash),
    EphPub = i2p_crypto:x25519_public_key(EphPriv),
    EncRecord = <<HopTrunc/binary, EphPub/binary, CT/binary, Tag/binary>>,
    {EncRecord, H2, Ck1}.

-doc """
Decrypt a build request record on the hop side using the Noise N pattern.

The hop locates its record beforehand with `f:find_own_record/2` (prefix
match on its truncated identity hash). The Noise N session is initialized
internally: the hop's full static public key is MixHashed in, mirroring
`f:encrypt_build_record/5`.

Input: `StaticPriv` — the hop's32-byte X25519 private key;
`HopFullPub` — the hop's own32-byte static X25519 public key;
`EncRecord` — the218-byte encrypted record.
Output: `{ok, Plaintext, H', Ck'}` on success — `H'` is the AEAD associated
data for this hop's reply record and `Ck'` feeds the reply/layer KDFs — or
`error` if authentication fails or the record is malformed.
""".
-spec decrypt_build_request_record(
    i2p_crypto:x25519_private_key(),
    i2p_crypto:x25519_public_key(),
    binary()
) -> {ok, binary(), i2p_crypto:hash(), i2p_crypto:chaining_key()} | error.
decrypt_build_request_record(StaticPriv, HopFullPub, EncRecord) when
    byte_size(EncRecord) =:= ?RECORD_SIZE
->
    <<_HopTrunc:?TRUNCATED_HASH_SIZE/binary, EphPub:32/binary, CT:154/binary, Tag:16/binary>> =
        EncRecord,
    {H0, Ck0} = i2p_crypto:noise_n_initialize(),
    H1 = i2p_crypto:mixhash(H0, HopFullPub),
    case i2p_crypto:noise_n_decrypt(StaticPriv, EphPub, H1, Ck0, CT, Tag) of
        {ok, Plaintext, H2, Ck1} -> {ok, Plaintext, H2, Ck1};
        error -> error
    end;
decrypt_build_request_record(_, _, _) ->
    error.

-doc """
Locate our record in a ShortTunnelBuild message by truncated identity hash.

Input: `OurIdHash` — our full 32-byte RouterIdentity hash; `Records` — the
list of 218-byte records carried by the message.
Output: `{ok, Index}` — the 0-based position of our record — or `error` when
no record is addressed to us.
""".
-spec find_own_record(i2p_crypto:hash(), [binary()]) -> {ok, non_neg_integer()} | error.
find_own_record(OurIdHash, Records) ->
    Prefix = truncated_identity_hash(OurIdHash),
    find_own_record(Prefix, Records, 0).

-doc """
Encrypt all build request records for a ShortTunnelBuild message.

Each record is encrypted independently (fresh Noise N state per hop); there
is no cross-record chaining state. Each finished record is then preprocessed
(symmetric encryption per the spec): concealed under the reply keys of every
earlier hop, so that when each earlier hop applies its own forward layering,
the layers cancel and the record becomes plaintext-readable exactly when it
reaches its owning hop.

Input: `Hops` — one `t:hop_desc/0` per real hop, in tunnel order;
`Plaintexts` — list of 154-byte plaintext records, same length as `Hops`;
`ObepPos` — the 0-based position of the outbound endpoint hop (whose IV key
uses the additional `"TunnelLayerIVKey"` derivation), or `none` when the last
hop is not an endpoint (e.g. inbound tunnels built through an existing
outbound tunnel).
Output: `{Records, HopKeys}` where `Records` are the218-byte encrypted,
preprocessed records in tunnel order and `HopKeys` carries, per position, the
reply/layer keys plus the final Noise hash — everything the creator needs to
process the OTBRM later.
""".
-spec encrypt_build_records([hop_desc()], [binary()], none | non_neg_integer()) ->
    {[binary()], [hop_build_keys()]}.
encrypt_build_records(Hops, Plaintexts, ObepPos) when length(Hops) =:= length(Plaintexts) ->
    {Records, Keys} =
        lists:foldl(
            fun(
                {#{eph_priv := EphPriv, hop_pub := HopPub, id_hash := IdHash}, Plaintext},
                {RAcc, KAcc}
            ) ->
                Index = length(RAcc),
                InitState = i2p_crypto:noise_n_initialize(),
                {EncRecord, Hf, Ck1} =
                    encrypt_build_record(EphPriv, HopPub, IdHash, InitState, Plaintext),
                Keys = (keys_for_role(Ck1, ObepPos, Index))#{noise_h => Hf},
                Concealed =
                    lists:foldl(
                        fun(#{reply_key := PrevReplyKey}, Acc) ->
                            encrypt_reply_layer(PrevReplyKey, Acc, Index)
                        end,
                        EncRecord,
                        KAcc
                    ),
                {[Concealed | RAcc], [Keys | KAcc]}
            end,
            {[], []},
            lists:zip(Hops, Plaintexts)
        ),
    {lists:reverse(Records), lists:reverse(Keys)}.

%%%%%%% %%% Reply/Layer KDF %%%%%%%

-doc """
Derive reply and layer keys from the chaining key (after build request record
encryption/decryption).

This is the non-OBEP path. Returns all three keys used for tunnel layer
encryption.

Input: `Ck` — the32-byte chaining key.
Output: a map with `reply_key`, `layer_key`, and `iv_key` (all32-byte
ChaCha20 keys).
""".
-spec derive_reply_layer_keys(i2p_crypto:chaining_key()) -> reply_layer_keys().
derive_reply_layer_keys(Ck) ->
    %% keydata = HKDF(ck, ZEROLEN, "SMTunnelReplyKey", 64)
    %% ck' = keydata[0:31]; replyKey = keydata[32:63]
    <<Ck1:32/binary, ReplyKey:32/binary>> = i2p_crypto:hkdf_sha256(
        Ck, <<>>, <<"SMTunnelReplyKey">>, 64
    ),
    %% keydata = HKDF(ck', ZEROLEN, "SMTunnelLayerKey", 64)
    %% ivKey = keydata[0:31] (the chaining key "because it's last");
    %% layerKey = keydata[32:63]
    <<IVKey:32/binary, LayerKey:32/binary>> = i2p_crypto:hkdf_sha256(
        Ck1, <<>>, <<"SMTunnelLayerKey">>, 64
    ),
    #{
        reply_key => ReplyKey,
        layer_key => LayerKey,
        iv_key => IVKey,
        rgarlic_key => undefined,
        rgarlic_tag => undefined
    }.

-doc """
Derive the OBEP-specific reply and layer keys.

The OBEP uses a different IV key derivation: after deriving the reply key and
layer key, it performs an additional HKDF step with `"TunnelLayerIVKey"`.

Input: `Ck` — the32-byte chaining key (from the OBEP's Noise N processing).
Output: a map with `reply_key`, `layer_key`, `iv_key` (all32-byte ChaCha20
keys).
""".
-spec derive_obep_keys(i2p_crypto:chaining_key()) -> reply_layer_keys().
derive_obep_keys(Ck) ->
    %% keydata = HKDF(ck, ZEROLEN, "SMTunnelReplyKey", 64)
    %% ck' = keydata[0:31]; replyKey = keydata[32:63]
    <<Ck1:32/binary, ReplyKey:32/binary>> = i2p_crypto:hkdf_sha256(
        Ck, <<>>, <<"SMTunnelReplyKey">>, 64
    ),
    %% keydata = HKDF(ck', ZEROLEN, "SMTunnelLayerKey", 64)
    %% ck'' = keydata[0:31]; layerKey = keydata[32:63]
    <<Ck2:32/binary, LayerKey:32/binary>> = i2p_crypto:hkdf_sha256(
        Ck1, <<>>, <<"SMTunnelLayerKey">>, 64
    ),
    %% keydata = HKDF(ck'', ZEROLEN, "TunnelLayerIVKey", 64)
    %% ck''' = keydata[0:31]; ivKey = keydata[32:63]
    <<Ck3:32/binary, IVKey:32/binary>> = i2p_crypto:hkdf_sha256(
        Ck2, <<>>, <<"TunnelLayerIVKey">>, 64
    ),
    %% keydata = HKDF(ck''', ZEROLEN, "RGarlicKeyAndTag", 64)
    %% garlicReplyTag = keydata[0:7] (8 bytes); garlicReplyKey = keydata[32:63]
    <<RgCk:32/binary, RGarlicKey:32/binary>> = i2p_crypto:hkdf_sha256(
        Ck3, <<>>, <<"RGarlicKeyAndTag">>, 64
    ),
    <<RGarlicTag:8/binary, _/binary>> = RgCk,
    #{
        reply_key => ReplyKey,
        layer_key => LayerKey,
        iv_key => IVKey,
        rgarlic_key => RGarlicKey,
        rgarlic_tag => RGarlicTag
    }.

%%%%%%% %%% Reply Record Encryption/Decryption %%%%%%%

-doc """
Seal the OBEP's own reply record (ChaCha20-Poly1305 AEAD).

A hop seals its own reply record with the reply key and the Noise hash
`H` as associated data. Every participating hop (transit or endpoint)
does this before forwarding; the nonce is the record position (0–7).

Input: `ReplyKey` — 32-byte reply key from `f:derive_reply_layer_keys/1`
or `f:derive_obep_keys/1`;
`ReplyPlaintext` — the 202-byte plaintext reply record;
`H` — the Noise chaining hash captured at build time; `RecordPosition`
— the hop's own record position (0-based, 0–7).
Output: the 218-byte encrypted record (ciphertext ‖ tag).
""".
-spec encrypt_reply_record(
    i2p_crypto:key(),
    binary(),
    i2p_crypto:hash(),
    non_neg_integer()
) -> binary().
encrypt_reply_record(ReplyKey, ReplyPlaintext, H, RecordPosition) when
    byte_size(ReplyPlaintext) =:= ?REPLY_PLAINTEXT_SIZE,
    RecordPosition >= 0,
    RecordPosition =< 7
->
    Nonce = i2p_crypto:es_nonce(RecordPosition),
    i2p_crypto:chacha20_poly1305_seal(ReplyKey, Nonce, ReplyPlaintext, H).

-doc """
Open one hop's own reply record (ChaCha20-Poly1305 AEAD).

The creator calls this for each hop's record after stripping the relay
layers above it. The nonce is the record position (0–7); the AD is the
Noise hash `H` captured at build time.

Input: `ReplyKey` — 32-byte reply key;
`EncReply` — the 218-byte encrypted record (ciphertext ‖ tag);
`H` — the Noise chaining hash; `RecordPosition` — the record's position
(0–7).
Output: `{ok, Plaintext}` (202 bytes) or `error`.
""".
-spec decrypt_reply_record(
    i2p_crypto:key(),
    binary(),
    i2p_crypto:hash(),
    non_neg_integer()
) -> {ok, binary()} | error.
decrypt_reply_record(ReplyKey, EncReply, H, RecordPosition) when
    byte_size(EncReply) =:= ?RECORD_SIZE,
    RecordPosition >= 0,
    RecordPosition =< 7
->
    Nonce = i2p_crypto:es_nonce(RecordPosition),
    i2p_crypto:chacha20_poly1305_open(ReplyKey, Nonce, EncReply, H);
decrypt_reply_record(_, _, _, _) ->
    error.

-doc """
Apply one iterative ChaCha20 layer to a reply record.

Every hop applies this to all records EXCEPT its own slot while propagating
the OTBRM backward. Both the hop's own AEAD seal and these stream layers use
the SAME key — the hop's reply key — so callers pass `reply_key` here, not
`layer_key`. The 12-byte IV has the record position little-endian at bytes
4–11.

Input: `Key` —32-byte ChaCha20 key (the hop's reply key); `Plaintext` —
the218-byte record; `RecordPosition` — the record's position (0–7).
Output: the218-byte encrypted record.
""".
-spec encrypt_reply_layer(i2p_crypto:key(), binary(), 0..7) -> binary().
encrypt_reply_layer(Key, Plaintext, RecordPosition) when
    byte_size(Plaintext) =:= ?RECORD_SIZE,
    RecordPosition >= 0,
    RecordPosition =< 7
->
    IV = <<0:32, RecordPosition:64/little-unsigned>>,
    i2p_crypto:chacha20_crypt(Key, IV, Plaintext).

-doc """
Remove one iterative ChaCha20 layer from a reply record.

ChaCha20 is a stream cipher, so decryption is the same operation as
encryption. The creator peels each slot's surviving layers — the reply keys
of hops processed after the slot's owner (see `f:encrypt_reply_layer/3` and
`m:i2p_tunnel:process_otbrm/2`).

Input: `Key` —32-byte ChaCha20 key (the layering hop's reply key); `Layered` —
the218-byte record; `RecordPosition` — the record's position (0–7).
Output: the218-byte record with one layer removed.
""".
-spec decrypt_reply_layer(i2p_crypto:key(), binary(), 0..7) -> binary().
decrypt_reply_layer(Key, Layered, RecordPosition) when
    byte_size(Layered) =:= ?RECORD_SIZE,
    RecordPosition >= 0,
    RecordPosition =< 7
->
    IV = <<0:32, RecordPosition:64/little-unsigned>>,
    i2p_crypto:chacha20_crypt(Key, IV, Layered).

%%%%%%% %%% Internal %%%%%%%

find_own_record(_Prefix, [], _Index) ->
    error;
find_own_record(
    Prefix,
    [<<Prefix:?TRUNCATED_HASH_SIZE/binary, _/binary>> | _Rest],
    Index
) ->
    {ok, Index};
find_own_record(Prefix, [_Other | Rest], Index) ->
    find_own_record(Prefix, Rest, Index + 1).

keys_for_role(Ck1, ObepPos, ObepPos) ->
    derive_obep_keys(Ck1);
keys_for_role(Ck1, _ObepPos, _Index) ->
    derive_reply_layer_keys(Ck1).
