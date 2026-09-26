-module(i2p_router_info).

-moduledoc """
RouterInfo and RouterAddress structures for the NTCP2 and SSU2 transports.

A RouterInfo is a router's self-signed network card: an identity, a publish
timestamp, its reachable addresses (transport style, cost, expiration, options)
and an Ed25519 signature over everything before it. This module builds, signs,
parses and verifies RouterInfos, and produces the m3p2 payload block that a
router sends in the NTCP2 handshake's msg3.

Wire format (`router_ident ‖ publishedDate ‖ addresses ‖ psiz ‖ options ‖
signature`, from the [common-structures spec](https://i2p.net/en/docs/specs/common-structures/)):

```
router_ident    identity bytes (>= 387); the m:i2p_keys structure, variable length
publishedDate   8 bytes big-endian, ms since epoch, 0 = null
size            1 byte, number of RouterAddress entries
RouterAddress   cost (1) ‖ expiration (8) ‖ transport_style (String)
                ‖ options (Mapping)
psiz            1 byte, number of peers (always 0)
options         Mapping of router-wide properties
signature       Ed25519 (64 bytes) over everything before it
```

A RouterAddress is:

```
cost             1 byte, lower = higher priority (NTCP2 published = 3,
                 non-published = 14, matching i2pd COST_NTCP2_*)
expiration       8 bytes big-endian; must be 0 on the wire
transport_style  String (for example, "NTCP2" or "SSU2")
options          Mapping of address properties
```

The NTCP2 address block options (i2pd `LocalRouterInfo::WriteToStream`):

- published: `host=<ip>;port=<n>;i=<16-byte IV in I2P Base64>;s=<32-byte
  static X25519 pub in I2P Base64>;v=2`
- non-published: `caps=<4|6>;s=<static key Base64>;v=2`

Options keys are sorted when encoded (the spec requires sorted order for the
signature to be reproducible). The RouterInfo signature is the Ed25519
signature over all bytes up to (not including) the signature itself; `parse/1`
verifies it.

Validation follows i2pd's `ReadFromBuffer`: a null or past timestamp, a missing
`netId=2` option, a missing `router.version`, no NTCP2 address with a valid
static key, or a bad signature all reject the RouterInfo. Non-published NTCP2
addresses are valid NetDb records; the stricter direct-connector check is
applied only by `ntcp2_connector/1`. Static keys and IVs are checked for length
(32/16 bytes).

## Usage

```erlang
%% Build and sign a RouterInfo for a published NTCP2 address.
Addr = i2p_router_info:ntcp2_address(<<"192.0.2.1">>, 4668, StaticPub, IV),
Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
RI = i2p_router_info:build(Identity, NowMs, [Addr], Opts, SigningSeed),
Bin = i2p_router_info:to_binary(RI),
{ok, RI} = i2p_router_info:parse(Bin),                  %% re-verify signature
{ok, #{host := H, port := P, static := S, iv := I}} = i2p_router_info:ntcp2_connector(RI),
Payload = i2p_router_info:m3p2_block(RI),               %% msg3 part 2 block
```

`ntcp2_connector/1` extracts what `i2p_ntcp2:alice_init/5` needs to start a
handshake to a peer: host, port, static X25519 key and IV from a published
NTCP2 address. A non-published address has no direct connector and is rejected
with `no_reachable_ntcp2`. `m3p2_block/1` wraps a RouterInfo as the type-2
(`RouterInfo`) block of the msg3 payload that `i2p_ntcp2:create_msg3/2`
encrypts.
""".

-export([
    build/5,
    parse/1,
    decode/1,
    parse_address/1,
    encode_address/1,
    ntcp2_address/4,
    ntcp2_nonpublished_address/2,
    ssu2_address/4,
    ssu2_introducer_address/4,
    ssu2_address_options/1,
    m3p2_block/1,
    to_binary/1,
    identity/1,
    hash/1,
    published/1,
    addresses/1,
    options/1,
    signing_key/1,
    ntcp2_connector/1,
    parse_mapping/1,
    encode_mapping/1,
    caps_string/3,
    validate_caps/1
]).

-export_type([router_info/0, router_address/0, mapping/0, introducer/0]).

-define(COST_NTCP2_PUBLISHED, 3).
-define(COST_NTCP2_NON_PUBLISHED, 14).
-define(KEYS_REGION_SIZE, 384).
-define(SIG_LEN, 64).
-define(MAX_INTRODUCERS, 3).

-doc """
An introducer this router relies on, as published in the `ih<i>`/`itag<i>`/
`iexp<i>` options of its SSU2 address.

`hash` is the 32-byte introducer router hash, `tag` the relay tag the
introducer handed out to us, and `exp` its optional Unix-second expiry after
which the introduction must be re-requested (absent when the introducer did
not publish an expiry).
""".
-type introducer() :: #{
    hash := binary(),
    tag := 1..16#FFFFFFFF,
    exp => pos_integer()
}.

-doc """
A parsed RouterInfo: the full signed wire bytes plus the extracted fields.
""".
-opaque router_info() :: #{
    binary := binary(),
    identity := i2p_keys:identity(),
    published := non_neg_integer(),
    addresses := [router_address()],
    options := mapping(),
    signature := i2p_crypto:ed25519_signature()
}.

-doc """
A single RouterAddress: `transport` is the style string, `cost` the 1-byte
priority (lower = higher), `expiration` the 8-byte expiration (0 on the wire),
`options` the address Mapping.
""".
-type router_address() :: #{
    transport := binary(),
    cost := byte(),
    expiration := non_neg_integer(),
    options := mapping()
}.

-doc """
A key/value option map, serialized as `String key = String value ;` pairs in
sorted key order with a 2-byte big-endian size of the pairs.
""".
-type mapping() :: #{binary() => binary()}.

-doc """
Build and sign a RouterInfo.

Input: `Identity` — the router's identity; `Published` — publish timestamp in
ms since epoch; `Addresses` — the RouterAddress entries; `Options` — the
router-wide Mapping; `SigningSeed` — the Ed25519 seed whose public key matches
`Identity`'s signing key.
Output: a `router_info()` with a fresh Ed25519 signature over all bytes before
it. `psiz` is always 0.
""".
-spec build(
    i2p_keys:identity(),
    non_neg_integer(),
    [router_address()],
    mapping(),
    i2p_crypto:ed25519_seed()
) -> router_info().
build(Identity, Published, Addresses, Options, SigningSeed) when
    is_integer(Published), Published >= 0
->
    Body =
        <<
            (i2p_keys:to_binary(Identity))/binary,
            Published:64/big,
            (length(Addresses)):8,
            (encode_addresses(Addresses))/binary,
            0:8,
            (encode_mapping(Options))/binary
        >>,
    Signature = i2p_crypto:ed25519_sign(Body, SigningSeed),
    #{
        binary => <<Body/binary, Signature/binary>>,
        identity => Identity,
        published => Published,
        addresses => Addresses,
        options => Options,
        signature => Signature
    };
build(_Identity, _Published, _Addresses, _Options, _SigningSeed) ->
    error(badarg).

-doc """
Parse and verify a RouterInfo.

Input: `Bin` — the full signed wire bytes.
Output: `{ok, router_info()}` when the structure is well-formed, the signature
verifies, the timestamp is non-zero, `netId=2` is present, `router.version` is
present, and an NTCP2 address with a valid static key is available;
`{error, Reason}` otherwise. Reasons: `too_short`, `malformed`,
`{bad_identity, _}`, `{bad_timestamp, 0}`, `bad_signature`,
`net_id_mismatch`, `missing_router_version`, `no_reachable_ntcp2`,
`{bad_static_key, _}`, `{bad_iv, _}`.
""".
-spec parse(binary()) -> {ok, router_info()} | {error, term()}.
parse(Bin) when is_binary(Bin) ->
    case parse_impl(Bin) of
        {ok, RI} -> validate(RI);
        {error, Reason} -> {error, Reason}
    end;
parse(_) ->
    {error, badarg}.

-doc """
Decode a RouterInfo without the strict `f:parse/1` reachability checks.

Input: `Bin` — the full signed wire bytes.
Output: `{ok, router_info()}` when the structure is well-formed and the
Ed25519 signature verifies, or `{error, Reason}` otherwise. Unlike
`f:parse/1`, this does not require `netId=2`, `router.version`, a reachable
NTCP2 address or a non-zero timestamp — use it to inspect foreign RouterInfos
(e.g. a peer netDb) where those properties may legitimately differ.
""".
-spec decode(binary()) -> {ok, router_info()} | {error, term()}.
decode(Bin) when is_binary(Bin) ->
    parse_impl(Bin);
decode(_) ->
    {error, badarg}.

-doc """
Parse a single RouterAddress entry.

Input: `Bin` — one address's wire bytes (cost ‖ expiration ‖ style ‖ options).
Output: `{ok, router_address()}` on success, `error` if the bytes are not a
well-formed address.
""".
-spec parse_address(binary()) -> {ok, router_address()} | error.
parse_address(Bin) when is_binary(Bin) ->
    case parse_address_impl(Bin) of
        {ok, Addr, <<>>} -> {ok, Addr};
        _ -> error
    end;
parse_address(_) ->
    error.

-doc """
Serialize a RouterAddress to its wire bytes.
""".
-spec encode_address(router_address()) -> binary().
encode_address(#{transport := Transport, cost := Cost, expiration := Expiration, options := Options}) ->
    <<Cost:8, Expiration:64/big, (byte_size(Transport)):8, Transport/binary,
        (encode_mapping(Options))/binary>>.

-doc """
Build a published NTCP2 RouterAddress.

Input: `Host` — IP address string (binary); `Port` — TCP port; `StaticKey` — a
32-byte X25519 public key; `IV` — a 16-byte IV.
Output: a `router_address()` with transport `<<"NTCP2">>`, cost 3, expiration
0, and options `host`, `port`, `i` (IV, I2P Base64), `s` (static key, I2P
Base64), `v=2` and `caps` (`<<"4">>` for an IPv4 host, `<<"6">>` for IPv6),
matching i2pd's published NTCP2 address.
""".
-spec ntcp2_address(
    binary(),
    1..65535,
    i2p_crypto:x25519_public_key(),
    i2p_crypto:aes_iv()
) -> router_address().
ntcp2_address(Host, Port, StaticKey, IV) when
    is_binary(Host),
    is_integer(Port),
    Port >= 1,
    Port =< 65535,
    byte_size(StaticKey) =:= 32,
    byte_size(IV) =:= 16
->
    Caps = family_caps(Host),
    #{
        transport => <<"NTCP2">>,
        cost => ?COST_NTCP2_PUBLISHED,
        expiration => 0,
        options => #{
            <<"host">> => Host,
            <<"port">> => integer_to_binary(Port),
            <<"i">> => i2p_keys:encode_b64(IV),
            <<"s">> => i2p_keys:encode_b64(StaticKey),
            <<"v">> => <<"2">>,
            <<"caps">> => Caps
        }
    };
ntcp2_address(_Host, _Port, _StaticKey, _IV) ->
    error(badarg).

-doc """
Build a non-published NTCP2 RouterAddress for a firewalled client.

Input: `Family` — `ipv4` or `ipv6`; `StaticKey` — the 32-byte X25519
public key. Output: a cost-14 NTCP2 address carrying only the family cap,
static key, and protocol version. The address deliberately has no host, port,
or IV because it cannot be used for an inbound connection.
""".
-spec ntcp2_nonpublished_address(ipv4 | ipv6, i2p_crypto:x25519_public_key()) ->
    router_address().
ntcp2_nonpublished_address(Family, StaticKey) when
    (Family =:= ipv4 orelse Family =:= ipv6),
    is_binary(StaticKey),
    byte_size(StaticKey) =:= 32
->
    Caps =
        case Family of
            ipv4 -> <<"4">>;
            ipv6 -> <<"6">>
        end,
    #{
        transport => <<"NTCP2">>,
        cost => ?COST_NTCP2_NON_PUBLISHED,
        expiration => 0,
        options => #{
            <<"caps">> => Caps,
            <<"s">> => i2p_keys:encode_b64(StaticKey),
            <<"v">> => <<"2">>
        }
    };
ntcp2_nonpublished_address(_Family, _StaticKey) ->
    error(badarg).

-doc """
Build an SSU2 RouterAddress announcing `Host`:`Port`.

Input: host IP string; port; our X25519 static public key (option `s`) and
our 32-byte introduction key (option `i`), both I2P Base64; version fixed
to `v=2`. The `caps` option advertises the host family (`4`/`6`) plus `B`
when this router participates in SSU2 peer tests (Bob relay / Charlie
tester capability, see `docs/protocol.md`).
Output: a `t:router_address/0` with transport style `SSU2`.
""".
-spec ssu2_address(binary(), 1..65535, i2p_crypto:x25519_public_key(), binary()) ->
    router_address().
ssu2_address(Host, Port, StaticKey, IntroKey) when
    is_binary(Host),
    is_integer(Port),
    Port >= 1,
    Port =< 65535,
    byte_size(StaticKey) =:= 32,
    byte_size(IntroKey) =:= 32
->
    #{
        transport => <<"SSU2">>,
        cost => ?COST_NTCP2_PUBLISHED,
        expiration => 0,
        options => #{
            <<"host">> => Host,
            <<"port">> => integer_to_binary(Port),
            <<"i">> => i2p_keys:encode_b64(IntroKey),
            <<"s">> => i2p_keys:encode_b64(StaticKey),
            <<"v">> => <<"2">>,
            <<"caps">> => ssu2_caps(Host)
        }
    };
ssu2_address(_Host, _Port, _StaticKey, _IntroKey) ->
    error(badarg).

-doc """
Build a non-published SSU2 RouterAddress announcing this router's introducers.

Input: `Host` — an IP string whose family becomes the `caps` letter (the host
itself is *not* published: the address is not directly dialable); `StaticKey` —
our 32-byte X25519 static public key (option `s`); `IntroKey` — our 32-byte
introduction key (option `i`); `Introducers` — up to three `t:introducer/0`
entries.
Output: a `t:router_address/0` with transport style `SSU2`, the non-published
cost (14), no `host`/`port` options, family `caps`, and the indexed introducer
options `ih<i>`/`itag<i>`/`iexp<i>` (exact key scheme of i2pd's
`ih`/`itag`/`iexp` and i2p-java's `PROP_INTRO_*`), with `exp` omitted for an
introducer that carries none.
""".
-spec ssu2_introducer_address(
    binary(),
    i2p_crypto:x25519_public_key(),
    binary(),
    [introducer()]
) -> router_address().
ssu2_introducer_address(Host, StaticKey, IntroKey, Introducers) when
    is_binary(Host),
    byte_size(StaticKey) =:= 32,
    byte_size(IntroKey) =:= 32,
    is_list(Introducers)
->
    #{
        transport => <<"SSU2">>,
        cost => ?COST_NTCP2_NON_PUBLISHED,
        expiration => 0,
        options =>
            maps:merge(
                introducer_options(Introducers),
                #{
                    <<"i">> => i2p_keys:encode_b64(IntroKey),
                    <<"s">> => i2p_keys:encode_b64(StaticKey),
                    <<"v">> => <<"2">>,
                    <<"caps">> => family_caps(Host)
                }
            )
    };
ssu2_introducer_address(_Host, _StaticKey, _IntroKey, _Introducers) ->
    error(badarg).

introducer_options(Introducers) ->
    introducer_options(Introducers, 0, #{}).

introducer_options([], _Index, Acc) ->
    Acc;
introducer_options(
    [#{hash := Hash, tag := Tag} = Intro | Rest],
    Index,
    Acc
) when
    Index < ?MAX_INTRODUCERS,
    is_binary(Hash),
    byte_size(Hash) =:= 32,
    is_integer(Tag),
    Tag >= 1,
    Tag =< 16#FFFFFFFF
->
    IndexBin = integer_to_binary(Index),
    Acc1 =
        Acc#{
            <<"ih", IndexBin/binary>> => i2p_keys:encode_b64(Hash),
            <<"itag", IndexBin/binary>> => integer_to_binary(Tag)
        },
    Acc2 =
        case maps:get(exp, Intro, undefined) of
            Exp when is_integer(Exp), Exp > 0 ->
                Acc1#{<<"iexp", IndexBin/binary>> => integer_to_binary(Exp)};
            _ ->
                Acc1
        end,
    introducer_options(Rest, Index + 1, Acc2);
introducer_options(_Introducers, _Index, _Acc) ->
    error(badarg).

-doc """
Extract the SSU2 connection parameters published in a RouterInfo.

Input: a decoded RouterInfo.
Output: `{ok, #{published := boolean(), host := undefined | binary(),
port := undefined | 1..65535, static_key := key(), intro_key := key(),
peer_test := boolean(), introducer := boolean(), introducers := [introducer()]}}`
from the first `SSU2`-style address carrying valid `s`/`i`/`v=2` options;
`peer_test`/`introducer` are `true` when the advertised `caps` includes the `B`
peer-test / `C` introducer capability, and `introducers` lists the published
`ih<i>`/`itag<i>`/`iexp<i>` entries. A dialable address has
`published := true` with its `host`/`port`; a firewalled router publishes a
non-published address (`published := false`, `host := undefined`,
`port := undefined`) that must be reached through its `introducers`. `error`
when no usable address exists.
""".
-spec ssu2_address_options(router_info()) ->
    {ok, #{
        published := boolean(),
        host := undefined | binary(),
        port := undefined | 1..65535,
        static_key := i2p_crypto:x25519_public_key(),
        intro_key := binary(),
        peer_test := boolean(),
        introducer := boolean(),
        introducers := [introducer()]
    }}
    | error.
ssu2_address_options(RI) ->
    ssu2_opts(maps:get(addresses, RI, [])).

ssu2_opts([Addr | Rest]) ->
    case maps:get(transport, Addr) of
        <<"SSU", _/binary>> ->
            Opts = maps:get(options, Addr),
            try_opts(Opts);
        _Other ->
            ssu2_opts(Rest)
    end;
ssu2_opts([]) ->
    error.

try_opts(Opts = #{<<"s">> := SB64, <<"i">> := IB64, <<"v">> := <<"2">>}) ->
    case {i2p_keys:decode_b64(SB64), i2p_keys:decode_b64(IB64)} of
        {SKey = <<_:256>>, IKey = <<_:256>>} ->
            Caps = maps:get(<<"caps">>, Opts, <<>>),
            Base = #{
                static_key => SKey,
                intro_key => IKey,
                peer_test => caps_has($B, Caps),
                introducer => caps_has($C, Caps),
                introducers => parse_introducers(Opts)
            },
            case published_endpoint(Opts) of
                {ok, Host, Port} ->
                    {ok, Base#{published => true, host => Host, port => Port}};
                unreachable ->
                    case maps:get(introducers, Base) of
                        [] -> error;
                        _ -> {ok, Base#{published => false, host => undefined, port => undefined}}
                    end
            end;
        _ ->
            error
    end;
try_opts(_Missing) ->
    error.

%% A published SSU2 address carries `host` and `port`; a firewalled one
%% carries neither but (when reachable at all) lists introducers instead.
published_endpoint(Opts) ->
    case maps:get(<<"host">>, Opts, undefined) of
        Host when is_binary(Host) ->
            case catch binary_to_integer(maps:get(<<"port">>, Opts, <<"0">>)) of
                Port when is_integer(Port), Port >= 1, Port =< 65535 -> {ok, Host, Port};
                _ -> unreachable
            end;
        _ ->
            unreachable
    end.

%% Indexed introducer options (i2pd `ih`/`itag`/`iexp`, i2p-java
%% `PROP_INTRO_*`): up to `?MAX_INTRODUCERS` entries, each requiring at least
%% a hash and a tag; a missing `iexp` leaves `exp` unset.
parse_introducers(Opts) ->
    [
        Intro
     || Intro <- [parse_introducer(Opts, I) || I <- lists:seq(0, ?MAX_INTRODUCERS - 1)],
        Intro =/= undefined
    ].

parse_introducer(Opts, Index) ->
    IndexBin = integer_to_binary(Index),
    case
        {
            maps:get(<<"ih", IndexBin/binary>>, Opts, undefined),
            maps:get(<<"itag", IndexBin/binary>>, Opts, undefined)
        }
    of
        {IH64, ITagB} when is_binary(IH64), is_binary(ITagB) ->
            case {decode_key_value(IH64), catch binary_to_integer(ITagB)} of
                {{ok, <<_:256>> = Hash}, Tag} when
                    is_integer(Tag), Tag >= 1, Tag =< 16#FFFFFFFF
                ->
                    case parse_introducer_exp(Opts, IndexBin) of
                        undefined -> #{hash => Hash, tag => Tag};
                        Exp -> #{hash => Hash, tag => Tag, exp => Exp}
                    end;
                _ ->
                    undefined
            end;
        _ ->
            undefined
    end.

parse_introducer_exp(Opts, IndexBin) ->
    case maps:get(<<"iexp", IndexBin/binary>>, Opts, undefined) of
        undefined ->
            undefined;
        ExpB ->
            case catch binary_to_integer(ExpB) of
                Exp when is_integer(Exp), Exp > 0 -> Exp;
                _ -> undefined
            end
    end.

-doc """
Wrap a RouterInfo as the type-2 (`RouterInfo`) block of the msg3 payload.

Input: `RI` — a parsed or built RouterInfo.
Output: the block bytes `<<2, size:16/big, 0, RI/binary>>` — block type 2,
size = RouterInfo length + 1 (the flag byte), flag 0, then the RouterInfo.
Feed the result to `i2p_ntcp2:create_msg3/2`.
""".
-spec m3p2_block(router_info()) -> binary().
m3p2_block(#{binary := Bin}) ->
    <<2:8, (byte_size(Bin) + 1):16/big, 0:8, Bin/binary>>.

-doc """
Return the full signed wire bytes of the RouterInfo.
""".
-spec to_binary(router_info()) -> binary().
to_binary(#{binary := Bin}) ->
    Bin.

-doc """
Return the router's identity.
""".
-spec identity(router_info()) -> i2p_keys:identity().
identity(#{identity := Identity}) ->
    Identity.

-doc """
Return the router hash: SHA-256 of the identity (the NetDb key).
""".
-spec hash(router_info()) -> i2p_crypto:hash().
hash(#{identity := Identity}) ->
    i2p_keys:hash(Identity).

-doc """
Return the publish timestamp in ms since epoch.
""".
-spec published(router_info()) -> non_neg_integer().
published(#{published := Published}) ->
    Published.

-doc """
Return the RouterAddress entries.
""".
-spec addresses(router_info()) -> [router_address()].
addresses(#{addresses := Addresses}) ->
    Addresses.

-doc """
Return the router-wide options Mapping.
""".
-spec options(router_info()) -> mapping().
options(#{options := Options}) ->
    Options.

-doc """
Return the Ed25519 signing public key (for verification).
""".
-spec signing_key(router_info()) -> i2p_crypto:ed25519_public_key().
signing_key(#{identity := Identity}) ->
    i2p_keys:signing_key(Identity).

-doc """
Extract the direct connect information from a peer's published NTCP2 address.

Input: `RI` — a parsed RouterInfo from the peer. Non-published NTCP2
addresses are valid for NetDb storage but are not dialable.
Output: `{ok, #{host, port, static, iv}}` when a published NTCP2 address with
a valid static key and IV is present; `{error, Reason}` otherwise
(`too_short`, `bad_signature`, `no_reachable_ntcp2`, `{bad_static_key, _}`,
`{bad_iv, _}`).
""".
-spec ntcp2_connector(router_info()) ->
    {ok, #{
        host := binary(),
        port := 1..65535,
        static := i2p_crypto:x25519_public_key(),
        iv := i2p_crypto:aes_iv()
    }}
    | {error, term()}.
ntcp2_connector(#{addresses := Addresses}) ->
    case find_reachable_ntcp2(Addresses) of
        {ok, #{options := Options}} ->
            case
                {
                    maps:get(<<"host">>, Options, undefined),
                    maps:get(<<"port">>, Options, undefined),
                    maps:get(<<"s">>, Options, undefined),
                    maps:get(<<"i">>, Options, undefined)
                }
            of
                {Host, PortB, S, I} when
                    is_binary(Host),
                    is_binary(PortB),
                    is_binary(S),
                    is_binary(I)
                ->
                    case decode_key_value(S) of
                        {ok, Static} when byte_size(Static) =:= 32 ->
                            case decode_key_value(I) of
                                {ok, IV} when byte_size(IV) =:= 16 ->
                                    {ok, #{
                                        host => Host,
                                        port => binary_to_integer(PortB),
                                        static => Static,
                                        iv => IV
                                    }};
                                {ok, _} ->
                                    {error, {bad_iv, I}};
                                error ->
                                    {error, {bad_iv, I}}
                            end;
                        {ok, _} ->
                            {error, {bad_static_key, S}};
                        error ->
                            {error, {bad_static_key, S}}
                    end;
                _ ->
                    {error, no_reachable_ntcp2}
            end;
        error ->
            {error, no_reachable_ntcp2}
    end.

-doc """
Parse a Mapping (`2-byte size ‖ String key = String value ;` pairs).

Input: `Bin` — the Mapping bytes including the size prefix.
Output: `{ok, mapping()}` if `Bin` is exactly one well-formed Mapping,
`error` otherwise.
""".
-spec parse_mapping(binary()) -> {ok, mapping()} | error.
parse_mapping(Bin) when is_binary(Bin) ->
    case parse_mapping_impl(Bin) of
        {ok, Map, <<>>} -> {ok, Map};
        _ -> error
    end;
parse_mapping(_) ->
    error.

-doc """
Serialize a Mapping to wire bytes (keys in sorted order).
""".
-spec encode_mapping(mapping()) -> binary().
encode_mapping(Options) when is_map(Options) ->
    Entries = lists:sort(maps:to_list(Options)),
    Pairs = [encode_mapping_pair(Key, Value) || {Key, Value} <- Entries],
    PairsBin = iolist_to_binary(Pairs),
    <<(byte_size(PairsBin)):16/big, PairsBin/binary>>;
encode_mapping(_) ->
    error(badarg).

%%%%%%% %%% Internal %%%%%%%

parse_impl(Bin) ->
    Size = byte_size(Bin),
    case Size >= ?KEYS_REGION_SIZE + 3 + 9 + 2 + ?SIG_LEN of
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

parse_body(Identity, <<Published:64/big, NumAddrs:8, AddrsAndPeers/binary>>, Bin) ->
    case parse_addresses(AddrsAndPeers, NumAddrs) of
        {ok, Addresses, <<Psiz:8, PeersBin/binary>>} when Psiz =:= 0 ->
            case parse_mapping_impl(PeersBin) of
                {ok, Options, <<Sig:?SIG_LEN/binary>>} ->
                    BodyOffset = byte_size(Bin) - ?SIG_LEN,
                    <<Body:BodyOffset/binary, _Sig:?SIG_LEN/binary>> = Bin,
                    SignPub = i2p_keys:signing_key(Identity),
                    case i2p_crypto:ed25519_verify(Body, Sig, SignPub) of
                        true ->
                            {ok, #{
                                binary => Bin,
                                identity => Identity,
                                published => Published,
                                addresses => Addresses,
                                options => Options,
                                signature => Sig
                            }};
                        false ->
                            {error, bad_signature}
                    end;
                _ ->
                    {error, malformed}
            end;
        _ ->
            {error, malformed}
    end;
parse_body(_Identity, _Rest, _Bin) ->
    {error, malformed}.

parse_addresses(Bin, 0) ->
    {ok, [], Bin};
parse_addresses(AddrBin, Num) when Num > 0 ->
    case parse_address_impl(AddrBin) of
        {ok, Addr, Rest} ->
            case parse_addresses(Rest, Num - 1) of
                {ok, Addrs, Rest2} -> {ok, [Addr | Addrs], Rest2};
                error -> error
            end;
        error ->
            error
    end;
parse_addresses(_AddrBin, _Num) ->
    error.

parse_address_impl(
    <<Cost:8, Expiration:64/big, StyleLen:8, Style:StyleLen/binary, OptionsBin/binary>>
) ->
    case parse_mapping_impl(OptionsBin) of
        {ok, Options, Rest} ->
            {ok, #{transport => Style, cost => Cost, expiration => Expiration, options => Options},
                Rest};
        error ->
            error
    end;
parse_address_impl(_) ->
    error.

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
    <<KeyLen:8, Key:KeyLen/binary, $=, ValLen:8, Val:ValLen/binary, $;, Rest/binary>>, Acc
) ->
    parse_mapping_entries(Rest, Acc#{Key => Val});
parse_mapping_entries(_, _) ->
    error.

encode_mapping_pair(Key, Value) ->
    <<(byte_size(Key)):8, Key/binary, $=, (byte_size(Value)):8, Value/binary, $;>>.

encode_addresses(Addresses) ->
    iolist_to_binary([encode_address(A) || A <- Addresses]).

validate(#{published := 0}) ->
    {error, {bad_timestamp, 0}};
validate(#{options := Options} = RI) ->
    case maps:get(<<"netId">>, Options, undefined) of
        <<"2">> ->
            case maps:get(<<"router.version">>, Options, undefined) of
                undefined ->
                    {error, missing_router_version};
                _ ->
                    case find_ntcp2(maps:get(addresses, RI)) of
                        {ok, _} -> {ok, RI};
                        {error, Reason} -> {error, Reason};
                        error -> {error, no_reachable_ntcp2}
                    end
            end;
        _ ->
            {error, net_id_mismatch}
    end.

find_ntcp2([Addr | Rest]) ->
    case maps:get(transport, Addr) of
        <<"NTCP2">> ->
            Options = maps:get(options, Addr),
            case maps:get(<<"s">>, Options, undefined) of
                undefined ->
                    find_ntcp2(Rest);
                Encoded ->
                    case decode_key_value(Encoded) of
                        {ok, Key} when byte_size(Key) =:= 32 -> {ok, Addr};
                        _ -> {error, {bad_static_key, Encoded}}
                    end
            end;
        _ ->
            find_ntcp2(Rest)
    end;
find_ntcp2([]) ->
    error.

find_reachable_ntcp2([Addr | Rest]) ->
    case maps:get(transport, Addr) of
        <<"NTCP2">> ->
            Options = maps:get(options, Addr),
            case
                {
                    maps:get(<<"host">>, Options, undefined),
                    maps:get(<<"s">>, Options, undefined)
                }
            of
                {_, undefined} ->
                    find_reachable_ntcp2(Rest);
                {undefined, _} ->
                    find_reachable_ntcp2(Rest);
                _ ->
                    {ok, Addr}
            end;
        _ ->
            find_reachable_ntcp2(Rest)
    end;
find_reachable_ntcp2([]) ->
    error.

decode_key_value(B64) ->
    try i2p_keys:decode_b64(B64) of
        Bin -> {ok, Bin}
    catch
        error:badarg -> error
    end.

%% Address-level `caps` flag from the host family: `4` for IPv4, `6` for
%% IPv6 — i2pd reads this to recognize the NTCP2 transport as IPv4/6.
family_caps(Host) ->
    case inet:parse_ipv4_address(binary_to_list(Host)) of
        {ok, _} -> <<"4">>;
        {error, _} -> <<"6">>
    end.

%% SSU2 `caps` capability string: host family letter plus `B` (peer tests).
%% The letters form a set, order-insensitive; `B` is what a Bob looks for
%% when choosing a relay target and a Charlie when answering a test.
ssu2_caps(Host) ->
    <<(family_caps(Host))/binary, "B">>.

caps_has(Cap, Caps) when is_binary(Caps) ->
    binary:match(Caps, <<Cap>>) =/= nomatch.

%%%%%%% %%% Router-level caps (% caps) %%%%%%%

-define(BANDWIDTH_CLASSES, [
    $K, $L, $M, $N, $O, $P, $X
]).
-define(FLOODFILL, $f).

-doc """
Compose the router-level `caps` option value per the current NetDb spec.

A router-wide `caps` string must carry exactly one bandwidth class letter
(`K`/`L`/`M`/`N`/`O`/`P`/`X`), at most one reachability flag (`R` reachable /
`U` unreachable), the floodfill marker `f` when the router is a floodfill, and
no other letters. Omitting the reject-tunnels flag `G` and providing a
bandwidth class is what advertises transit eligibility — peers parse a fully
specified `caps` and treat the router as a transit-default participant.

Input: `Bandwidth` — one of the bandwidth class letters (uppercase); `Reachable`
— `true` when the router has a dialable public address, `false` otherwise;
`Floodfill` — `true` when the router acts as a floodfill.
Output: the canonical `caps` value, e.g. `<<"RLf">>`, `<<"Ulf">>`, `<<"L">>`.
""".
-spec caps_string(char(), boolean(), boolean()) -> binary().
caps_string(Bandwidth, Reachable, Floodfill) ->
    case is_bandwidth(Bandwidth) of
        true ->
            Reach =
                case Reachable of
                    true -> "R";
                    false -> "U"
                end,
            FF =
                case Floodfill of
                    true -> "f";
                    false -> ""
                end,
            list_to_binary([Reach, [Bandwidth], FF]);
        false ->
            error({bad_caps_bandwidth, Bandwidth})
    end.

-doc """
Validate a router-level `caps` string against the current NetDb spec.

Input: `Bin` — the `caps` option value.
Output: `true` when the value is well-formed (exactly one bandwidth class
letter, at most one reachability flag, only legal letters, non-empty); `false`
otherwise. This mirrors go-i2p's `ValidateCapsString`/i2pd's checks so peers
accept our self-published RouterInfo and we can reject malformed foreign ones.
""".
-spec validate_caps(binary()) -> boolean().
validate_caps(Bin) when is_binary(Bin), byte_size(Bin) > 0 ->
    validate_caps_letters(binary_to_list(Bin), false, false, false);
validate_caps(_) ->
    false.

validate_caps_letters([], false, _Reach, _Flood) ->
    false;
validate_caps_letters([], true, _Reach, _Flood) ->
    true;
validate_caps_letters([C | Rest], HasB, Reach, Flood) ->
    case {C, Reach, Flood} of
        {$R, false, false} ->
            validate_caps_letters(Rest, HasB, true, Flood);
        {$U, false, false} ->
            validate_caps_letters(Rest, HasB, true, Flood);
        {?FLOODFILL, _, false} ->
            validate_caps_letters(Rest, HasB, Reach, true);
        _ ->
            case is_bandwidth(C) of
                true when HasB ->
                    false;
                true ->
                    validate_caps_letters(Rest, true, Reach, Flood);
                false ->
                    false
            end
    end.

is_bandwidth(C) ->
    lists:member(C, ?BANDWIDTH_CLASSES).
