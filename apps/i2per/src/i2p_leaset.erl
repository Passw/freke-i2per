-module(i2p_leaset).

-moduledoc """
LeaseSet2 (DatabaseStore `store_type` 3): a Destination's signed advertisement
of the tunnels it is willing to receive on.

A LeaseSet2 is how a client learns to reach a Destination: it carries the
Destination's identity, a publish date and lifetime, a set of up to 16 leases
— each `gateway ‖ tunnelID ‖ endDate` — and the Destination's Ed25519
signature. Routers store LeaseSets keyed by the Destination hash and serve
them to peers that look the Destination up. The router uses them for tunnel
building and SAM client delivery.

Wire format (`identity ‖ published ‖ expires ‖ flags ‖ properties ‖ keys ‖
leases ‖ signature`, from the
[LeaseSet2 spec](https://i2p.net/en/docs/spec/leaset-set/)):

```
identity       KeysAndCert, variable length (391 bytes for X25519 + Ed25519)
published      4 bytes big-endian, seconds since epoch
expires        2 bytes big-endian, lifetime in days
flags          2 bytes big-endian (0 = standard, published LeaseSet)
properties     Mapping (2-byte size + pairs; 00 00 when empty)
numKeys        1 byte, number of encryption keys (1 here)
key            per key: encType(2) ‖ keyLen(2) ‖ key — X25519 is
               encType 4, keyLen 32
numLeases      1 byte, number of leases (<= 16)
lease          40 bytes each: gateway(32) ‖ tunnelID(4 BE) ‖ endDate(4 BE, ms,
               wraps in 2106)
signature      Ed25519 (64 bytes) over the store-type byte ‖ everything before
```

The signature covers the **store-type byte (3) prepended** to the content, as
i2pd's `LeaseSet::ReadFromBuffer` computes it (`m_VerifyBuffer[0] = m_StoreType`).
In a DatabaseStore message that byte already precedes the LeaseSet payload, so
`f:to_binary/1` emits the content without it and `f:decode/1` expects the same;
`m:i2p_i2np` places the byte in the message body.

Only standard, published LeaseSets are supported. The offline-keys (`0x01`),
unpublished (`0x02`) and blinded (`0x04`) flag bits are rejected.

## Usage

```erlang
%% Build and sign a LeaseSet2 for our Destination
Leases = [#{gateway => RouterHash, tunnel_id => 0, end_date => NowMs + 60000}],
LS = i2p_leaset:build(Identity, NowSec, 7, Leases, SigningSeed),
Bin = i2p_leaset:to_binary(LS),                      %% content + signature
{ok, LS} = i2p_leaset:decode(Bin),                   %% re-verify signature
ok = i2p_leaset:valid(LS, NowSec),                   %% time-window checks
Key = i2p_leaset:hash(LS),                           %% NetDb key (Destination hash)
Msg = i2p_i2np:db_store(Key, i2p_leaset:store_type(), 0, undefined, Bin),
```
""".

-export([
    build/6,
    build/5,
    decode/1,
    to_binary/1,
    identity/1,
    published/1,
    expires/1,
    flags/1,
    properties/1,
    leases/1,
    keys/1,
    signature/1,
    hash/1,
    valid/2,
    store_type/0
]).
-export_type([lease_set/0, lease/0, ls_key/0]).

-define(STORE_TYPE_LEASESET2, 3).
-define(KEYS_REGION_SIZE, 384).
-define(SIG_LEN, 64).
-define(CRYPT_TYPE_X25519, 4).
-define(KEY_LEN_X25519, 32).
-define(LEASE_SIZE, 40).
-define(MAX_NUM_LEASES, 16).
-define(FLAG_OFFLINE, 16#01).
-define(FLAG_UNPUBLISHED, 16#02).
-define(FLAG_BLINDED, 16#04).
-define(SECONDS_PER_DAY, 86400).
%% i2pd LeaseSet.hpp: LEASESET_EXPIRATION_TIME_THRESHOLD = 12*60*1000 ms — a
%% lease set counts as usable until this long past its published lifetime.
-define(EXPIRE_THRESHOLD, 12 * 60).
%% Future-tolerance matches the NetDb RouterInfo window (2 minutes).
-define(FUTURE_TOLERANCE, 2 * 60).

-doc """
A parsed LeaseSet2: the full signed content bytes (without the store-type
byte) plus the extracted fields.
""".
-opaque lease_set() :: #{
    binary := binary(),
    identity := i2p_keys:identity(),
    published := 0..16#FFFFFFFF,
    expires := 0..16#FFFF,
    flags := 0..16#FFFF,
    properties := i2p_router_info:mapping(),
    leases := [lease()],
    keys := [ls_key()],
    signature := i2p_crypto:ed25519_signature()
}.

-doc """
A single lease: the 32-byte tunnel gateway hash, the 4-byte tunnel ID (0 for a
direct gateway) and the `end_date` in ms since epoch. Like i2pd/Java, the
wire field is 32 bits and wraps in 2106; `build/6` truncates the value with
`EndDate band 16#FFFFFFFF`, and `decode/1` returns the truncated value.
""".
-type lease() :: #{
    gateway := i2p_crypto:hash(),
    tunnel_id := 0..16#FFFFFFFF,
    end_date := non_neg_integer()
}.

-doc """
An encryption key in a LeaseSet2: `enc_type` (4 = X25519) and the raw `key`
bytes (32 for X25519).
""".
-type ls_key() :: #{enc_type := 0..16#FFFF, key := binary()}.

-doc "DatabaseStore `store_type` 3 — a standard LeaseSet2.".
-spec store_type() -> 3.
store_type() -> ?STORE_TYPE_LEASESET2.

-doc """
Build and sign a standard LeaseSet2.

Input: `Identity` — the Destination identity; `PublishedSec` — publish time in
seconds since epoch; `ExpiresDays` — lifetime in days (16-bit); `Properties` —
the LeaseSet Mapping (empty `#{}` allowed); `Leases` — up to 16
`t:lease/0` entries; `SigningSeed` — the Ed25519 seed whose public key matches
`Identity`'s signing key.
Output: a `t:lease_set/0` with a fresh Ed25519 signature over
`store_type ‖ content`, one X25519 encryption key (from `Identity`'s crypto
key) and flags 0.
""".
-spec build(
    i2p_keys:identity(),
    0..16#FFFFFFFF,
    0..16#FFFF,
    i2p_router_info:mapping(),
    [lease()],
    i2p_crypto:ed25519_seed()
) -> lease_set().
build(Identity, PublishedSec, ExpiresDays, Properties, Leases, SigningSeed) when
    is_integer(PublishedSec),
    PublishedSec >= 0,
    PublishedSec =< 16#FFFFFFFF,
    is_integer(ExpiresDays),
    ExpiresDays >= 0,
    ExpiresDays =< 16#FFFF,
    is_map(Properties),
    is_list(Leases),
    length(Leases) =< ?MAX_NUM_LEASES
->
    Head = <<
        (i2p_keys:to_binary(Identity))/binary,
        PublishedSec:32/big,
        ExpiresDays:16/big,
        0:16/big,
        (i2p_router_info:encode_mapping(Properties))/binary
    >>,
    CryptoKey = i2p_keys:public_key(Identity),
    Keys =
        <<1:8, ?CRYPT_TYPE_X25519:16/big, ?KEY_LEN_X25519:16/big, CryptoKey/binary>>,
    LeasesBin = iolist_to_binary([encode_lease(Lease) || Lease <- Leases]),
    Body = <<Head/binary, Keys/binary, (length(Leases)):8, LeasesBin/binary>>,
    Signature = i2p_crypto:ed25519_sign(<<?STORE_TYPE_LEASESET2:8, Body/binary>>, SigningSeed),
    #{
        binary => <<Body/binary, Signature/binary>>,
        identity => Identity,
        published => PublishedSec,
        expires => ExpiresDays,
        flags => 0,
        properties => Properties,
        leases => Leases,
        keys => [#{enc_type => ?CRYPT_TYPE_X25519, key => CryptoKey}],
        signature => Signature
    };
build(_Identity, _PublishedSec, _ExpiresDays, _Properties, _Leases, _SigningSeed) ->
    error(badarg).

-doc """
Build a LeaseSet2 with an empty properties Mapping.

Input: as `f:build/6` minus `Properties`. Output: a `t:lease_set/0` whose
`properties` is `#{}`.
""".
-spec build(
    i2p_keys:identity(),
    0..16#FFFFFFFF,
    0..16#FFFF,
    [lease()],
    i2p_crypto:ed25519_seed()
) -> lease_set().
build(Identity, PublishedSec, ExpiresDays, Leases, SigningSeed) ->
    build(Identity, PublishedSec, ExpiresDays, #{}, Leases, SigningSeed).

-doc """
Parse and verify a LeaseSet2.

Input: `Bin` — the full signed content bytes, **without** the DatabaseStore
store-type byte.
Output: `{ok, t:lease_set/0}` when the structure is well-formed, the
store-type byte parses as 3, the Ed25519 signature verifies and the flags are
0; `{error, Reason}` otherwise. Reasons: `too_short`, `malformed`,
`{bad_identity, _}`, `{unsupported_flags, Flags}`, `bad_signature`.
""".
-spec decode(binary()) -> {ok, lease_set()} | {error, term()}.
decode(Bin) when is_binary(Bin) ->
    case parse_impl(Bin) of
        {ok, LS} -> {ok, LS};
        {error, Reason} -> {error, Reason}
    end;
decode(_) ->
    {error, badarg}.

-doc """
Return the full signed content bytes (without the store-type byte).

Feed the result to `m:i2p_i2np` `f:m:i2p_i2np:db_store/5` as `Data`, which
prepends the store-type byte in the DatabaseStore body.
""".
-spec to_binary(lease_set()) -> binary().
to_binary(#{binary := Bin}) ->
    Bin.

-doc "Return the Destination identity.".
-spec identity(lease_set()) -> i2p_keys:identity().
identity(#{identity := Identity}) ->
    Identity.

-doc "Return the publish time in seconds since epoch.".
-spec published(lease_set()) -> 0..16#FFFFFFFF.
published(#{published := Published}) ->
    Published.

-doc "Return the lifetime in days (16-bit).".
-spec expires(lease_set()) -> 0..16#FFFF.
expires(#{expires := Expires}) ->
    Expires.

-doc "Return the 16-bit flags (0 for a standard, published LeaseSet).".
-spec flags(lease_set()) -> 0..16#FFFF.
flags(#{flags := Flags}) ->
    Flags.

-doc "Return the LeaseSet properties Mapping.".
-spec properties(lease_set()) -> i2p_router_info:mapping().
properties(#{properties := Properties}) ->
    Properties.

-doc "Return the leases (up to 16).".
-spec leases(lease_set()) -> [lease()].
leases(#{leases := Leases}) ->
    Leases.

-doc "Return the encryption keys (one X25519 key here).".
-spec keys(lease_set()) -> [ls_key()].
keys(#{keys := Keys}) ->
    Keys.

-doc "Return the Ed25519 signature (64 bytes).".
-spec signature(lease_set()) -> i2p_crypto:ed25519_signature().
signature(#{signature := Signature}) ->
    Signature.

-doc """
Return the Destination hash: SHA-256 of the identity (the NetDb key).
""".
-spec hash(lease_set()) -> i2p_crypto:hash().
hash(#{identity := Identity}) ->
    i2p_keys:hash(Identity).

-doc """
Check a LeaseSet2 against i2pd's time-window rules.

Input: `LS` — a parsed LeaseSet; `NowSec` — wall-clock seconds since epoch.
Output: `ok` when the publish date is not more than 2 minutes into the future
and the published lifetime plus the 12-minute threshold has not fully passed;
`{error, from_future}` or `{error, expired}` otherwise.
""".
-spec valid(lease_set(), non_neg_integer()) -> ok | {error, from_future | expired}.
valid(#{published := Published}, NowSec) when
    is_integer(NowSec), NowSec >= 0, Published > NowSec + ?FUTURE_TOLERANCE
->
    {error, from_future};
valid(#{published := Published, expires := Expires}, NowSec) when
    is_integer(NowSec),
    NowSec >= 0,
    Published + Expires * ?SECONDS_PER_DAY + ?EXPIRE_THRESHOLD < NowSec
->
    {error, expired};
valid(#{published := _, expires := _}, NowSec) when is_integer(NowSec), NowSec >= 0 ->
    ok;
valid(_LS, _NowSec) ->
    error(badarg).

%%%%%%% %%% Internal %%%%%%%

parse_impl(Bin) ->
    Size = byte_size(Bin),
    case Size >= ?KEYS_REGION_SIZE + 3 + 4 + 2 + 2 + 2 + 1 + 1 + ?SIG_LEN of
        true ->
            <<Keys:?KEYS_REGION_SIZE/binary, CertType:8, CertLen:16/big, Rest0/binary>> = Bin,
            case Rest0 of
                <<CertPayload:CertLen/binary, Rest/binary>> ->
                    IdentityBin =
                        <<Keys:?KEYS_REGION_SIZE/binary, CertType:8, CertLen:16/big,
                            CertPayload/binary>>,
                    case i2p_keys:parse(IdentityBin) of
                        {ok, Identity} ->
                            parse_body(Identity, Rest, Bin);
                        {error, Reason} ->
                            {error, {bad_identity, Reason}}
                    end;
                _ ->
                    {error, too_short}
            end;
        false ->
            {error, too_short}
    end.

parse_body(
    Identity,
    <<Published:32/big, Expires:16/big, 0:16/big, Rest0/binary>>,
    Bin
) ->
    case parse_mapping_impl(Rest0) of
        {ok, Properties, Rest1} ->
            case Rest1 of
                <<NumKeys:8, Rest2/binary>> when NumKeys >= 1, NumKeys =< 255 ->
                    case parse_keys(Rest2, NumKeys) of
                        {ok, Keys, Rest3} ->
                            case Rest3 of
                                <<NumLeases:8, Rest4/binary>> when NumLeases =< ?MAX_NUM_LEASES ->
                                    case parse_leases(Rest4, NumLeases) of
                                        {ok, Leases, Rest5} ->
                                            case Rest5 of
                                                <<Sig:?SIG_LEN/binary>> ->
                                                    BodyOffset = byte_size(Bin) - ?SIG_LEN,
                                                    <<Body:BodyOffset/binary, _:?SIG_LEN/binary>> =
                                                        Bin,
                                                    SignPub = i2p_keys:signing_key(Identity),
                                                    case
                                                        i2p_crypto:ed25519_verify(
                                                            <<?STORE_TYPE_LEASESET2:8,
                                                                Body/binary>>,
                                                            Sig,
                                                            SignPub
                                                        )
                                                    of
                                                        true ->
                                                            {ok, #{
                                                                binary => Bin,
                                                                identity => Identity,
                                                                published => Published,
                                                                expires => Expires,
                                                                flags => 0,
                                                                properties => Properties,
                                                                leases => Leases,
                                                                keys => Keys,
                                                                signature => Sig
                                                            }};
                                                        false ->
                                                            {error, bad_signature}
                                                    end;
                                                _ ->
                                                    {error, malformed}
                                            end;
                                        error ->
                                            {error, malformed}
                                    end;
                                _ ->
                                    {error, malformed}
                            end;
                        error ->
                            {error, malformed}
                    end;
                _ ->
                    {error, malformed}
            end;
        error ->
            {error, malformed}
    end;
parse_body(_Identity, <<_:32/big, _:16/big, Flags:16/big, _/binary>>, _Bin) when
    Flags =/= 0
->
    {error, {unsupported_flags, Flags}};
parse_body(_Identity, _Rest, _Bin) ->
    {error, malformed}.

parse_keys(Bin, 0) ->
    {ok, [], Bin};
parse_keys(<<EncType:16/big, KeyLen:16/big, Key:KeyLen/binary, Rest/binary>>, Num) when
    Num > 0,
    KeyLen >= 1,
    KeyLen =< 512
->
    case parse_keys(Rest, Num - 1) of
        {ok, Keys, Rest2} ->
            {ok, [#{enc_type => EncType, key => Key} | Keys], Rest2};
        error ->
            error
    end;
parse_keys(_, _) ->
    error.

parse_leases(Bin, 0) ->
    {ok, [], Bin};
parse_leases(
    <<Gateway:32/binary, TunnelID:32/big, EndDate:32/big, Rest/binary>>,
    Num
) when Num > 0 ->
    case parse_leases(Rest, Num - 1) of
        {ok, Leases, Rest2} ->
            Lease = #{gateway => Gateway, tunnel_id => TunnelID, end_date => EndDate},
            {ok, [Lease | Leases], Rest2};
        error ->
            error
    end;
parse_leases(_, _) ->
    error.

encode_lease(#{gateway := Gateway, tunnel_id := TunnelID, end_date := EndDate}) when
    is_binary(Gateway),
    byte_size(Gateway) =:= 32,
    is_integer(TunnelID),
    TunnelID >= 0,
    TunnelID =< 16#FFFFFFFF,
    is_integer(EndDate),
    EndDate >= 0
->
    <<Gateway/binary, TunnelID:32/big, (EndDate band 16#FFFFFFFF):32/big>>;
encode_lease(_) ->
    error(badarg).

parse_mapping_impl(<<Size:16/big, Entries:Size/binary, Rest/binary>>) ->
    case parse_mapping_entries(Entries, #{}) of
        {ok, Map} -> {ok, Map, Rest};
        error -> error
    end;
parse_mapping_impl(_) ->
    error.

parse_mapping_entries(<<>>, Acc) ->
    {ok, Acc};
parse_mapping_entries(
    <<KeyLen:8, Key:KeyLen/binary, $=, ValLen:8, Val:ValLen/binary, $;, Rest/binary>>,
    Acc
) ->
    parse_mapping_entries(Rest, Acc#{Key => Val});
parse_mapping_entries(_, _) ->
    error.
