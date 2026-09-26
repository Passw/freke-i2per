-module(i2p_i2np).

-moduledoc """
The I2NP message layer: short and standard message headers, network database
messages, and tunnel, garlic, and build-message wire formats.

I2NP (I2P Network Protocol) sits above the transports and carries
router-to-router messages. Over [NTCP2](https://i2p.net/en/docs/specs/ntcp2)
each I2NP message travels in a data-phase block of type 3, whose 2-byte size
covers a **short header** plus the message body:

```text
type(1) ‖ msg_id(4) ‖ short_expiration(4) ‖ body
```

The body length is the block size minus 9 (the header); there is no length
field or checksum in the short header — both come from the enclosing block and
the AEAD frame. The 4-byte `short_expiration` is seconds since the epoch
(wraps in 2106).

When I2NP messages are wrapped inside tunnels or garlic cloves, a **standard
16-byte header** is used instead:

```text
type(1) ‖ msg_id(4) ‖ expiration_ms(8) ‖ size(2) ‖ checksum(1) ‖ body
```

The `checksum` is the first byte of SHA-256(body); it is computed on encode
but tolerated on decode (some routers emit 0 when re-wrapping short-header
messages).

This module implements:

- `f:encode/1` / `f:decode/1` — the short-header envelope (9 bytes, NTCP2).
- `f:encode_std/1` / `f:decode_std/1` — the standard 16-byte header envelope
  (tunnels and garlic).
- The network database messages: DatabaseStore
  (`f:db_store/5`), DatabaseLookup (`f:db_lookup/4`), DatabaseSearchReply
  (`f:db_search_reply/3`) and DeliveryStatus (`f:delivery_status/2`), each as
  an `t:i2np_message/0` that `f:encode/1` serializes.
- RouterInfo gzip for DatabaseStore payloads (`f:gzip_router_info/1`,
  `f:router_info_data/1`), matching the Java header
  `1F 8B 08 00 00 00 00 00 02 FF` (mtime 0, XFL 2, OS 0xFF) that the I2NP
  spec recommends for fingerprint resistance.
- Garlic Message (`f:garlic/1`), TunnelData (`f:tunnel_data/1`),
  TunnelGateway (`f:tunnel_gateway/2`), ShortTunnelBuild
  (`f:short_tunnel_build/1`) and OutboundTunnelBuildReply
  (`f:outbound_tunnel_build_reply/1`) message builders and decoders.
- Parsers for each message body (`f:decode_db_store/1`,
  `f:decode_db_lookup/1`, `f:decode_db_search_reply/1`,
  `f:decode_delivery_status/1`, `f:decode_garlic/1`,
  `f:decode_tunnel_data/1`, `f:decode_tunnel_gateway/1`,
  `f:decode_short_tunnel_build/1`, `f:decode_outbound_tunnel_build_reply/1`).

The wire layouts below follow the
[I2NP specification](https://i2p.net/en/docs/spec/i2np); the offsets are also
covered in `docs/protocol.md`.

## Usage

```erlang
%% Wrap a RouterInfo into a DatabaseStore I2NP message and serialize it
Msg = i2p_i2np:db_store(Key, 0, 0, undefined,
                        i2p_i2np:router_info_data(RIBin)),
Wire = i2p_i2np:encode(Msg),                    %% 9-byte short header + body
{ok, Msg} = i2p_i2np:decode(Wire),              %% header round-trip

%% Ask a floodfill for the routers closest to a random key (exploration)
Lookup = i2p_i2np:db_lookup(Key, OurHash,
                            i2p_i2np:lookup_type_exploratory(), []),
{ok, #{peers := Peers, from := From}} =
    i2p_i2np:decode_db_search_reply(ReplyBody),

%% Build a standard-header message for tunnel wrapping
StdMsg = i2p_i2np:encode_std(#{type => 11, msg_id => <<1,2,3,4>>,
                                expiration_ms => 1800000000000,
                                body => <<42:32, 0:32>>}),
%% Wrap into a TunnelGateway (type 19)
GW = i2p_i2np:tunnel_gateway(777, StdMsg),
{ok, #{tunnel_id := 777, msg := _}} =
    i2p_i2np:decode_tunnel_gateway(maps:get(body, GW)).
```
""".

-export([
    encode/1,
    decode/1,
    encode_std/1,
    decode_std/1,
    db_store/5,
    db_lookup/4,
    db_lookup_via_tunnel/5,
    db_search_reply/3,
    delivery_status/2,
    garlic/1,
    tunnel_data/1,
    tunnel_gateway/2,
    short_tunnel_build/1,
    outbound_tunnel_build_reply/1,
    fresh_msg_id/0,
    router_info_data/1,
    parse_router_info_data/1,
    gzip_router_info/1,
    gunzip_router_info/1,
    decode_db_store/1,
    decode_db_lookup/1,
    decode_db_search_reply/1,
    decode_delivery_status/1,
    decode_garlic/1,
    decode_tunnel_data/1,
    decode_tunnel_gateway/1,
    decode_short_tunnel_build/1,
    decode_outbound_tunnel_build_reply/1,
    type_database_store/0,
    type_database_lookup/0,
    type_database_search_reply/0,
    type_delivery_status/0,
    type_garlic/0,
    type_tunnel_data/0,
    type_tunnel_gateway/0,
    type_short_tunnel_build/0,
    type_outbound_tunnel_build_reply/0,
    store_type_router_info/0,
    store_type_leaseset/0,
    lookup_type_any/0,
    lookup_type_leaseset/0,
    lookup_type_routerinfo/0,
    lookup_type_exploratory/0
]).
-export_type([
    i2np_message/0,
    std_message/0,
    message_type/0,
    message_id/0,
    short_expiration/0,
    db_store/0,
    db_lookup/0,
    db_search_reply/0,
    db_reply/0,
    garlic/0,
    tunnel_data/0,
    tunnel_gateway/0,
    tunnel_build_records/0,
    lookup_type/0
]).

-doc "A complete I2NP message: the short header fields plus the body.".
-type i2np_message() :: #{
    type := message_type(),
    msg_id := message_id(),
    expiration := short_expiration(),
    body := binary()
}.

-doc "The 1-byte I2NP message type (see `docs/protocol.md` for the table).".
-type message_type() :: 0..255.

-doc "The 4-byte big-endian message ID.".
-type message_id() :: <<_:32>>.

-doc """
The 4-byte big-endian expiration, seconds since the epoch (wraps in 2106).
Messages expiring too far in the future should be rejected; the recommended
maximum is 60 seconds ahead.
""".
-type short_expiration() :: 0..16#FFFFFFFF.

-doc """
A parsed DatabaseStore body.

- `key` — the 32-byte hash of the stored object (RouterIdentity hash for a
  RouterInfo).
- `store_type` — `0` RouterInfo, `1` LeaseSet, `3` LeaseSet2, `5`
  EncryptedLeaseSet, `7` MetaLeaseSet.
- `reply_token` — nonzero asks for a DeliveryStatus (and triggers floodfill
  re-flood).
- `reply` — `undefined`, or the `{TunnelID, GatewayHash}` the DeliveryStatus
  reply should go to (a zero tunnel ID means direct to `GatewayHash`).
- `data` — for `store_type` 0 a `size(2) ‖ gzip(RouterInfo)` blob
  (`f:parse_router_info_data/1`); otherwise the raw LeaseSet bytes.
""".
-type db_store() :: #{
    key := i2p_crypto:hash(),
    store_type := byte(),
    reply_token := 0..16#FFFFFFFF,
    reply := db_reply(),
    data := binary()
}.

-doc "The optional reply target of a `t:db_store/0` (`undefined` or `{TunnelID, Gateway}`).".
-type db_reply() :: undefined | {0..16#FFFFFFFF, i2p_crypto:hash()}.

-doc """
A standard 16-byte header I2NP message, used when messages are wrapped inside
tunnels or garlic cloves. Contrast the short 9-byte NTCP2 header which uses
4-byte seconds and no size/checksum fields.
""".
-type std_message() :: #{
    type := message_type(),
    msg_id := message_id(),
    expiration_ms := 0..16#FFFFFFFFFFFFFFFF,
    body := binary(),
    %% Computed by f:encode_std/1; present in maps returned by
    %% f:decode_std/1.
    checksum => 0..255
}.

-doc """
A parsed Garlic Message (type 11) body: `length` (byte count of `data`) and
`data` (the encrypted clove set, up to 64 KB).
""".
-type garlic() :: #{
    length := non_neg_integer(),
    data := binary()
}.

-doc """
A parsed TunnelData Message (type 18) body: `tunnel_id` (4 bytes, the next
hop's tunnel ID), `iv` (16-byte AES-256-CBC IV), and `encrypted` (1008 bytes
of layered-encrypted tunnel payload).
""".
-type tunnel_data() :: #{
    tunnel_id := 0..16#FFFFFFFF,
    iv := <<_:128>>,
    encrypted := <<_:8064>>,
    body := <<_:8224>>
}.

-doc """
A parsed TunnelGateway Message (type 19) body: `tunnel_id` (the tunnel to
forward into), `msg` (the standard-header I2NP message to fragment and
deliver), and `body` (the raw binary).
""".
-type tunnel_gateway() :: #{
    tunnel_id := 0..16#FFFFFFFF,
    msg := std_message(),
    body := binary()
}.

-doc """
A parsed ShortTunnelBuild (type 25) or OTBRM (type 26) body: `num` (1–8
records), `records` (list of 218-byte build/ reply records).
""".
-type tunnel_build_records() :: #{
    num := 1..8,
    records := [binary()]
}.

-doc "The DatabaseLookup reply delivery/encryption info used by the decoders.".
-type db_lookup() :: #{
    key := i2p_crypto:hash(),
    from := i2p_crypto:hash(),
    flags := byte(),
    type := lookup_type(),
    encrypted := boolean(),
    delivery := undefined | #{tunnel_id := 0..16#FFFFFFFF},
    excluded := [i2p_crypto:hash()],
    reply_encryption := binary()
}.

-doc "The DatabaseLookup type flag bits 3-2 (the lookup kinds).".
-type lookup_type() :: any | leaseset | routerinfo | exploratory.

-doc """
A parsed DatabaseSearchReply body: `key` (the hash searched for), `peers` (up
to 255 hashes the responder thinks are close to `key`), and `from` (the
responder's hash — unauthenticated, treat as advisory).
""".
-type db_search_reply() :: #{
    key := i2p_crypto:hash(),
    peers := [i2p_crypto:hash()],
    from := i2p_crypto:hash()
}.

-define(SHORT_HEADER_SIZE, 9).
-define(STD_HEADER_SIZE, 16).
-define(DB_STORE_ROUTER_INFO, 0).
-define(DB_STORE_LEASESET, 1).
-define(TYPE_DB_STORE, 1).
-define(TYPE_DB_LOOKUP, 2).
-define(TYPE_DB_SEARCH_REPLY, 3).
-define(TYPE_DELIVERY_STATUS, 10).
-define(TYPE_GARLIC, 11).
-define(TYPE_TUNNEL_DATA, 18).
-define(TYPE_TUNNEL_GATEWAY, 19).
-define(TYPE_SHORT_TUNNEL_BUILD, 25).
-define(TYPE_OTBRM, 26).
-define(LOOKUP_ANY, 16#00).
-define(LOOKUP_LEASESET, 16#04).
-define(LOOKUP_ROUTERINFO, 16#08).
-define(LOOKUP_EXPLORATORY, 16#0C).
-define(MAX_EXCLUDED, 512).
-define(MAX_SEARCH_REPLY_PEERS, 255).
-define(MAX_GARLIC_SIZE, 65536).
-define(TUNNEL_MESSAGE_SIZE, 1028).
-define(BUILD_RECORD_SIZE, 218).
-define(MAX_BUILD_RECORDS, 8).

-doc """
Serialize an `t:i2np_message/0` to its short-header wire form
(`type(1) ‖ msg_id(4) ‖ expiration(4) ‖ body`).
""".
-spec encode(i2np_message()) -> binary().
encode(#{type := Type, msg_id := MsgID, expiration := Expiration, body := Body}) ->
    <<Type:8, MsgID:4/binary, Expiration:32/big, Body/binary>>.

-doc """
Parse a short-header I2NP message.

Input: `Bin` — a short-header message (at least 9 bytes).
Output: `{ok, t:i2np_message/0}`, or `error` for a truncated header.
""".
-spec decode(binary()) -> {ok, i2np_message()} | error.
decode(<<Type:8, MsgID:32/big, Expiration:32/big, Body/binary>>) ->
    {ok, #{type => Type, msg_id => <<MsgID:32/big>>, expiration => Expiration, body => Body}};
decode(_) ->
    error.

-doc """
Serialize a standard 16-byte header I2NP message.

Input: `Msg` — a `t:std_message/0` map.
Output: the wire binary `type(1) ‖ msg_id(4) ‖ expiration_ms(8) ‖ size(2) ‖ checksum(1) ‖ body`.

The checksum is the first byte of SHA-256(body), computed on encode. On
decode the checksum is tolerated even if it does not match (some routers
emit a zero checksum when re-wrapping short-header messages).
""".
-spec encode_std(std_message()) -> binary().
encode_std(#{type := Type, msg_id := MsgID, expiration_ms := ExpirationMs, body := Body}) ->
    Size = byte_size(Body),
    Checksum = crypto:hash(sha256, Body),
    <<Checksum1:8, _/binary>> = Checksum,
    <<Type:8, MsgID:4/binary, ExpirationMs:64/big, Size:16/big, Checksum1:8, Body/binary>>.

-doc """
Parse a standard 16-byte header I2NP message.

Input: `Bin` — a standard-header message (at least 16 bytes).
Output: `{ok, t:std_message/0}`, or `error` for a truncated header or a
`size` field that does not match the available body. The checksum byte is
returned but never rejected (to tolerate i2pd's zero-checksum conversion).
""".
-spec decode_std(binary()) -> {ok, std_message()} | error.
decode_std(
    <<Type:8, MsgID:32/big, ExpirationMs:64/big, Size:16/big, Checksum:8, Body:Size/binary>>
) ->
    {ok, #{
        type => Type,
        msg_id => <<MsgID:32/big>>,
        expiration_ms => ExpirationMs,
        body => Body,
        checksum => Checksum
    }};
decode_std(_) ->
    error.

-doc "I2NP message type 1 — DatabaseStore.".
-spec type_database_store() -> 1.
type_database_store() -> ?TYPE_DB_STORE.

-doc "I2NP message type 2 — DatabaseLookup.".
-spec type_database_lookup() -> 2.
type_database_lookup() -> ?TYPE_DB_LOOKUP.

-doc "I2NP message type 3 — DatabaseSearchReply.".
-spec type_database_search_reply() -> 3.
type_database_search_reply() -> ?TYPE_DB_SEARCH_REPLY.

-doc "I2NP message type 10 — DeliveryStatus.".
-spec type_delivery_status() -> 10.
type_delivery_status() -> ?TYPE_DELIVERY_STATUS.

-doc "I2NP message type 11 — Garlic.".
-spec type_garlic() -> 11.
type_garlic() -> ?TYPE_GARLIC.

-doc "I2NP message type 18 — TunnelData.".
-spec type_tunnel_data() -> 18.
type_tunnel_data() -> ?TYPE_TUNNEL_DATA.

-doc "I2NP message type 19 — TunnelGateway.".
-spec type_tunnel_gateway() -> 19.
type_tunnel_gateway() -> ?TYPE_TUNNEL_GATEWAY.

-doc "I2NP message type 25 — ShortTunnelBuild (ECIES build request).".
-spec type_short_tunnel_build() -> 25.
type_short_tunnel_build() -> ?TYPE_SHORT_TUNNEL_BUILD.

-doc "I2NP message type 26 — OutboundTunnelBuildReply (OTBRM).".
-spec type_outbound_tunnel_build_reply() -> 26.
type_outbound_tunnel_build_reply() -> ?TYPE_OTBRM.

-doc "DatabaseStore `store_type` 0 — a compressed RouterInfo.".
-spec store_type_router_info() -> 0.
store_type_router_info() -> ?DB_STORE_ROUTER_INFO.

-doc "DatabaseStore `store_type` 1 — an uncompressed LeaseSet.".
-spec store_type_leaseset() -> 1.
store_type_leaseset() -> ?DB_STORE_LEASESET.

-doc "DatabaseLookup bits 3-2 `00` — ANY lookup (deprecated).".
-spec lookup_type_any() -> 0.
lookup_type_any() -> ?LOOKUP_ANY.

-doc "DatabaseLookup bits 3-2 `01` — LeaseSet lookup.".
-spec lookup_type_leaseset() -> 4.
lookup_type_leaseset() -> ?LOOKUP_LEASESET.

-doc "DatabaseLookup bits 3-2 `10` — RouterInfo lookup.".
-spec lookup_type_routerinfo() -> 8.
lookup_type_routerinfo() -> ?LOOKUP_ROUTERINFO.

-doc "DatabaseLookup bits 3-2 `11` — exploratory lookup (random key).".
-spec lookup_type_exploratory() -> 12.
lookup_type_exploratory() -> ?LOOKUP_EXPLORATORY.

-doc """
Build a Garlic Message I2NP message (type 11).

Input: `Data` — the encrypted clove set (0–64 KB).
Output: a complete `t:i2np_message/0` with a fresh random message ID and the
short expiration now + 8 s.
""".
-spec garlic(binary()) -> i2np_message().
garlic(Data) when is_binary(Data), byte_size(Data) =< ?MAX_GARLIC_SIZE ->
    Body = <<(byte_size(Data)):32/big, Data/binary>>,
    message(?TYPE_GARLIC, Body);
garlic(_) ->
    error(badarg).

-doc """
Build a TunnelData Message I2NP message (type 18).

Input: `TunnelMsg` — the raw 1028-byte tunnel message (`tunnel_id(4) ‖ iv(16) ‖ encrypted(1008)`).
Output: a complete `t:i2np_message/0`.
""".
-spec tunnel_data(binary()) -> i2np_message().
tunnel_data(<<_TunnelID:32/big, _IV:16/binary, _Encrypted:1008/binary>> = TunnelMsg) ->
    message(?TYPE_TUNNEL_DATA, TunnelMsg);
tunnel_data(_) ->
    error(badarg).

-doc """
Build a TunnelGateway Message I2NP message (type 19).

Input: `TunnelID` — the tunnel to forward into; `StdMsg` — the standard-header
I2NP message bytes (from `f:encode_std/1`), at most 65535 bytes.
Output: a complete `t:i2np_message/0` with the short header.
""".
-spec tunnel_gateway(0..16#FFFFFFFF, binary()) -> i2np_message().
tunnel_gateway(TunnelID, StdMsg) when
    is_integer(TunnelID),
    TunnelID >= 0,
    TunnelID =< 16#FFFFFFFF,
    is_binary(StdMsg),
    byte_size(StdMsg) =< 16#FFFF
->
    Size = byte_size(StdMsg),
    Body = <<TunnelID:32/big, Size:16/big, StdMsg/binary>>,
    message(?TYPE_TUNNEL_GATEWAY, Body);
tunnel_gateway(_, _) ->
    error(badarg).

-doc """
Build a ShortTunnelBuild I2NP message (type 25) for ECIES tunnel creation.

Input: `Records` — a list of 1 to 8 build request records, each exactly 218
bytes (encrypted with Noise N per the ECIES tunnel creation spec).
Output: a complete `t:i2np_message/0` with the short header.

The body is `num(1) ‖ records(num × 218)` where `num` is the record count.
""".
-spec short_tunnel_build([binary()]) -> i2np_message().
short_tunnel_build(Records) when
    is_list(Records),
    length(Records) >= 1,
    length(Records) =< ?MAX_BUILD_RECORDS
->
    pack_records(?TYPE_SHORT_TUNNEL_BUILD, Records);
short_tunnel_build(_) ->
    error(badarg).

-doc """
Build an OutboundTunnelBuildReply (OTBRM) I2NP message (type 26).

Input: `Records` — a list of 1 to 8 reply records, each exactly 218 bytes.
Output: a complete `t:i2np_message/0` with the short header.

The body is `num(1) ‖ records(num × 218)` where `num` is the record count.
""".
-spec outbound_tunnel_build_reply([binary()]) -> i2np_message().
outbound_tunnel_build_reply(Records) when
    is_list(Records),
    length(Records) >= 1,
    length(Records) =< ?MAX_BUILD_RECORDS
->
    pack_records(?TYPE_OTBRM, Records);
outbound_tunnel_build_reply(_) ->
    error(badarg).

-doc """
Build a DatabaseStore I2NP message (type 1).

Input: `Key` — the 32-byte hash of the stored object; `StoreType` — `0` for a
RouterInfo (`f:store_type_router_info/0`), `1` for a LeaseSet; `ReplyToken` —
0 for an unsolicited store, nonzero to request a DeliveryStatus (a floodfill
also re-floods the entry when this is nonzero); `Reply` — `undefined` or
`{TunnelID, GatewayHash}` (zero tunnel ID = direct); `Data` — the payload
(`f:router_info_data/1` output for a RouterInfo, raw bytes for a LeaseSet).

Output: a complete `t:i2np_message/0` with a fresh random message ID and an
expiration `now + 8s`.
""".
-spec db_store(i2p_crypto:hash(), byte(), 0..16#FFFFFFFF, db_reply(), binary()) ->
    i2np_message().
db_store(Key, StoreType, ReplyToken, Reply, Data) when
    is_binary(Key),
    byte_size(Key) =:= 32,
    StoreType >= 0,
    StoreType =< 255,
    ReplyToken >= 0,
    ReplyToken =< 16#FFFFFFFF,
    is_binary(Data)
->
    Body = db_store_body(Key, StoreType, ReplyToken, Reply, Data),
    message(?TYPE_DB_STORE, Body);
db_store(_Key, _StoreType, _ReplyToken, _Reply, _Data) ->
    error(badarg).

-doc """
Build a DatabaseLookup I2NP message (type 2).

Input: `Key` — the 32-byte hash to look up (a random key for exploration);
`From` — our RouterIdentity hash; `LookupType` — one of the `lookup_type_*`
flags; `Excluded` — hashes the responder must not return in a
DatabaseSearchReply (up to 512).

Output: a complete `t:i2np_message/0` with the direct-reply delivery flag
cleared and no reply encryption.
""".
-spec db_lookup(i2p_crypto:hash(), i2p_crypto:hash(), 0..255, [i2p_crypto:hash()]) ->
    i2np_message().
db_lookup(Key, From, LookupType, Excluded) when
    is_binary(Key),
    byte_size(Key) =:= 32,
    is_binary(From),
    byte_size(From) =:= 32,
    LookupType >= 0,
    LookupType =< 255,
    is_list(Excluded),
    length(Excluded) =< ?MAX_EXCLUDED
->
    message(?TYPE_DB_LOOKUP, lookup_body(Key, From, LookupType, none, Excluded));
db_lookup(_Key, _From, _LookupType, _Excluded) ->
    error(badarg).

-doc """
Build a DatabaseLookup I2NP message whose reply is routed into an inbound
tunnel.

Input: `Key` — the 32-byte hash to look up; `From` — our RouterIdentity hash
(the reply-tunnel gateway); `LookupType` — one of the `lookup_type_*` flags;
`ReplyTunnelID` — our inbound tunnel's receive ID; `Excluded` — hashes the
responder must not return (up to 512).

Output: a complete `t:i2np_message/0` with the tunnel-reply flag (bit 0) set
and the 4-byte tunnel ID placed before the excluded list, per the
DatabaseLookup layout.
""".
-spec db_lookup_via_tunnel(
    i2p_crypto:hash(),
    i2p_crypto:hash(),
    0..255,
    0..16#FFFFFFFF,
    [i2p_crypto:hash()]
) ->
    i2np_message().
db_lookup_via_tunnel(Key, From, LookupType, ReplyTunnelID, Excluded) when
    is_binary(Key),
    byte_size(Key) =:= 32,
    is_binary(From),
    byte_size(From) =:= 32,
    LookupType >= 0,
    LookupType =< 255,
    ReplyTunnelID >= 0,
    ReplyTunnelID =< 16#FFFFFFFF,
    is_list(Excluded),
    length(Excluded) =< ?MAX_EXCLUDED
->
    message(?TYPE_DB_LOOKUP, lookup_body(Key, From, LookupType, {ok, ReplyTunnelID}, Excluded));
db_lookup_via_tunnel(_Key, _From, _LookupType, _ReplyTunnelID, _Excluded) ->
    error(badarg).

-doc """
Build a DatabaseSearchReply I2NP message (type 3).

Input: `Key` — the hash that was searched; `Peers` — up to 255 hashes close to
`Key`; `From` — our RouterIdentity hash.
Output: a complete `t:i2np_message/0`.
""".
-spec db_search_reply(i2p_crypto:hash(), [i2p_crypto:hash()], i2p_crypto:hash()) ->
    i2np_message().
db_search_reply(Key, Peers, From) when
    is_binary(Key),
    byte_size(Key) =:= 32,
    is_list(Peers),
    length(Peers) =< ?MAX_SEARCH_REPLY_PEERS,
    is_binary(From),
    byte_size(From) =:= 32
->
    Body =
        <<Key/binary, (length(Peers)):8, (iolist_to_binary(Peers))/binary, From/binary>>,
    message(?TYPE_DB_SEARCH_REPLY, Body);
db_search_reply(_Key, _Peers, _From) ->
    error(badarg).

-doc """
Build a DeliveryStatus I2NP message (type 10).

Input: `MsgID` — the message ID being acknowledged; `TimeMs` — the 8-byte
timestamp, milliseconds since the epoch.
Output: a complete `t:i2np_message/0`.
""".
-spec delivery_status(message_id(), 0..16#FFFFFFFFFFFFFFFF) -> i2np_message().
delivery_status(MsgID, TimeMs) when
    is_binary(MsgID), byte_size(MsgID) =:= 4, TimeMs >= 0, TimeMs =< 16#FFFFFFFFFFFFFFFF
->
    message(?TYPE_DELIVERY_STATUS, <<MsgID/binary, TimeMs:64/big>>);
delivery_status(_MsgID, _TimeMs) ->
    error(badarg).

-doc """
Encode the DatabaseStore payload for a RouterInfo: `size(2) ‖ gzip(RouterInfo)`.

Input: `Bin` — the full signed RouterInfo bytes
(`m:i2p_router_info` `f:m:i2p_router_info:to_binary/1`).
Output: the store payload, ready for `f:db_store/5`.
""".
-spec router_info_data(binary()) -> <<_:16, _:_*8>>.
router_info_data(Bin) when is_binary(Bin) ->
    Gzipped = gzip_router_info(Bin),
    <<(byte_size(Gzipped)):16/big, Gzipped/binary>>.

-doc """
Extract the RouterInfo from a DatabaseStore payload.

Input: `Bin` — a `size(2) ‖ gzip` blob as produced by `f:router_info_data/1`.
Output: `{ok, RouterInfoBytes}` — the decompressed, still-signature-carrying
RouterInfo — or `error` for a truncated size or an invalid gzip stream.
""".
-spec parse_router_info_data(binary()) -> {ok, binary()} | error.
parse_router_info_data(<<Size:16/big, Gzipped:Size/binary, _/binary>>) ->
    gunzip_router_info(Gzipped);
parse_router_info_data(_) ->
    error.

-doc """
Gzip a RouterInfo into the I2P fingerprint format.

The output is a standard gzip frame whose 10-byte header is exactly
`1F 8B 08 00 00 00 00 00 02 FF` — modification time 0, XFL 2 (maximum
compression), OS 0xFF (unknown) — as the I2NP spec recommends so routers do
not leak their OS or build time.

Input: `Bin` — the bytes to compress.
Output: the gzip frame.
""".
-spec gzip_router_info(binary()) -> <<_:64, _:_*8>>.
gzip_router_info(Bin) when is_binary(Bin) ->
    Deflated = deflate_raw(Bin),
    <<16#1F, 16#8B, 8, 0, 0:32/big, 2, 16#FF, Deflated/binary, (crc32(Bin)):32/little,
        (byte_size(Bin)):32/little>>.

-doc """
Decompress a RouterInfo gzip frame.

Handles both standard deflate gzip frames and the stored (uncompressed)
deflate-block variant that i2pd's `GzipNoCompression` emits for small
RouterInfos.

Input: `Bin` — a gzip frame.
Output: `{ok, Decompressed}` or `error` on an invalid frame.
""".
-spec gunzip_router_info(binary()) -> {ok, binary()} | error.
gunzip_router_info(Bin) when is_binary(Bin) ->
    try
        {ok, zlib:gunzip(Bin)}
    catch
        _:_ -> error
    end;
gunzip_router_info(_) ->
    error.

-doc """
Parse a DatabaseStore body.

Input: `Body` — the I2NP message body of a type-1 message.
Output: `{ok, t:db_store/0}`, or `error` for a truncated body.
""".
-spec decode_db_store(binary()) -> {ok, db_store()} | error.
decode_db_store(<<Key:32/binary, StoreType:8, 0:32/big, Data/binary>>) ->
    {ok, #{key => Key, store_type => StoreType, reply_token => 0, reply => undefined, data => Data}};
decode_db_store(
    <<Key:32/binary, StoreType:8, ReplyToken:32/big, TunnelID:32/big, Gateway:32/binary,
        Data/binary>>
) when ReplyToken > 0 ->
    {ok, #{
        key => Key,
        store_type => StoreType,
        reply_token => ReplyToken,
        reply => {TunnelID, Gateway},
        data => Data
    }};
decode_db_store(_) ->
    error.

-doc """
Parse a DatabaseLookup body.

Input: `Body` — the I2NP message body of a type-2 message.
Output: `{ok, t:db_lookup/0}`, or `error` for a truncated body or an
overlong excluded-peer list. The lookup type is decoded from flags bits 3-2,
`encrypted` from bit 1, and any trailing reply-key/tags bytes are preserved
verbatim in `reply_encryption` (the peer manager does not use encrypted
replies).
""".
-spec decode_db_lookup(binary()) -> {ok, db_lookup()} | error.
decode_db_lookup(<<Key:32/binary, From:32/binary, Flags:8, Rest/binary>>) ->
    case split_lookup_tail(Flags, Rest) of
        {ok, Delivery, Excluded, Encryption} ->
            {ok, #{
                key => Key,
                from => From,
                flags => Flags,
                type => lookup_type_name(Flags),
                encrypted => (Flags band 16#02) =/= 0,
                delivery => Delivery,
                excluded => Excluded,
                reply_encryption => Encryption
            }};
        error ->
            error
    end;
decode_db_lookup(_) ->
    error.

-doc """
Parse a DatabaseSearchReply body.

Input: `Body` — the I2NP message body of a type-3 message.
Output: `{ok, t:db_search_reply/0}`, or `error` for a truncated body.
""".
-spec decode_db_search_reply(binary()) -> {ok, db_search_reply()} | error.
decode_db_search_reply(<<Key:32/binary, Num:8, Peers:(Num * 32)/binary, From:32/binary>>) when
    Num =< 64
->
    {ok, #{key => Key, peers => split_hashes(Peers), from => From}};
decode_db_search_reply(_) ->
    error.

-doc """
Parse a DeliveryStatus body.

Input: `Body` — the I2NP message body of a type-10 message.
Output: `{ok, MsgID, TimeMs}` — the acknowledged message ID and the 8-byte
millisecond timestamp — or `error`.
""".
-spec decode_delivery_status(binary()) -> {ok, message_id(), 0..16#FFFFFFFFFFFFFFFF} | error.
decode_delivery_status(<<MsgID:32/big, TimeMs:64/big>>) ->
    {ok, <<MsgID:32/big>>, TimeMs};
decode_delivery_status(_) ->
    error.

-doc """
Parse a Garlic Message body (type 11).

Input: `Body` — the I2NP message body of a type-11 message.
Output: `{ok, t:garlic/0}` — the length and encrypted data — or `error` for
a truncated body or a length field that does not match the data.
""".
-spec decode_garlic(binary()) -> {ok, garlic()} | error.
decode_garlic(<<Length:32/big, Data:Length/binary>>) ->
    {ok, #{length => Length, data => Data}};
decode_garlic(_) ->
    error.

-doc """
Parse a TunnelData Message body (type 18).

Input: `Body` — the I2NP message body of a type-18 message.
Output: `{ok, t:tunnel_data/0}` — the tunnel ID, IV, and encrypted payload —
or `error` if the body is not exactly 1028 bytes.
""".
-spec decode_tunnel_data(binary()) -> {ok, tunnel_data()} | error.
decode_tunnel_data(<<TunnelID:32/big, IV:16/binary, Encrypted:1008/binary>> = RawBody) ->
    {ok, #{tunnel_id => TunnelID, iv => IV, encrypted => Encrypted, body => RawBody}};
decode_tunnel_data(_) ->
    error.

-doc """
Parse a TunnelGateway Message body (type 19).

Input: `Body` — the I2NP message body of a type-19 message.
Output: `{ok, t:tunnel_gateway/0}` — the tunnel ID and the parsed inner
standard-header message — or `error` for a truncated body, an invalid inner
message, or a `size` field that does not match the inner message.
""".
-spec decode_tunnel_gateway(binary()) -> {ok, tunnel_gateway()} | error.
decode_tunnel_gateway(<<TunnelID:32/big, Size:16/big, StdMsg:Size/binary>>) ->
    case decode_std(StdMsg) of
        {ok, ParsedMsg} ->
            {ok, #{tunnel_id => TunnelID, msg => ParsedMsg, body => StdMsg}};
        error ->
            error
    end;
decode_tunnel_gateway(_) ->
    error.

-doc """
Parse a ShortTunnelBuild body (type 25).

Input: `Body` — the I2NP message body of a type-25 message.
Output: `{ok, t:tunnel_build_records/0}` — the record count and list of
218-byte records — or `error` for a body whose length does not equal
`1 + num × 218`, or `num` is outside the valid range 1–8.
""".
-spec decode_short_tunnel_build(binary()) -> {ok, tunnel_build_records()} | error.
decode_short_tunnel_build(<<Num:8, RecordsBin/binary>>) when
    Num >= 1,
    Num =< ?MAX_BUILD_RECORDS,
    byte_size(RecordsBin) =:= Num * ?BUILD_RECORD_SIZE
->
    Records = split_build_records(RecordsBin, Num, []),
    {ok, #{num => Num, records => Records}};
decode_short_tunnel_build(_) ->
    error.

-doc """
Parse an OutboundTunnelBuildReply body (type 26).

Input: `Body` — the I2NP message body of a type-26 message.
Output: `{ok, t:tunnel_build_records/0}`, or `error`.
""".
-spec decode_outbound_tunnel_build_reply(binary()) -> {ok, tunnel_build_records()} | error.
decode_outbound_tunnel_build_reply(<<Num:8, RecordsBin/binary>>) when
    Num >= 1,
    Num =< ?MAX_BUILD_RECORDS,
    byte_size(RecordsBin) =:= Num * ?BUILD_RECORD_SIZE
->
    Records = split_build_records(RecordsBin, Num, []),
    {ok, #{num => Num, records => Records}};
decode_outbound_tunnel_build_reply(_) ->
    error.

-doc """
A fresh 4-byte random message ID, the same generator every `f:db_store/5`-style
builder uses internally. Callers that craft message maps by hand (tunnel
managers relaying frames) use this so ID generation has one home.
""".
-spec fresh_msg_id() -> message_id().
fresh_msg_id() ->
    crypto:strong_rand_bytes(4).

%%%%%%% %%% Internal %%%%%%%

%% A complete I2NP message with a fresh random message ID and the short
%% expiration now + 8 s (the i2pd I2NP_MESSAGE_EXPIRATION_TIMEOUT).
message(Type, Body) ->
    #{
        type => Type,
        msg_id => fresh_msg_id(),
        expiration => expiration(),
        body => Body
    }.

expiration() ->
    erlang:system_time(second) + 8.

%% Split a binary of concatenated BUILD_RECORD_SIZE records into a list.
split_build_records(<<>>, 0, Acc) ->
    lists:reverse(Acc);
split_build_records(<<R:218/binary, Rest/binary>>, N, Acc) ->
    split_build_records(Rest, N - 1, [R | Acc]).

%% Verify that every record in the list is exactly BUILD_RECORD_SIZE bytes.
validate_build_records([]) ->
    ok;
validate_build_records([R | Rest]) when is_binary(R), byte_size(R) =:= ?BUILD_RECORD_SIZE ->
    validate_build_records(Rest);
validate_build_records(_) ->
    error.

%% pack_records/2 — the `num(1) ‖ records(num × 218)` body shared by the
%% ShortTunnelBuild and OTBRM builders; error(badarg) on a wrong-size record.
pack_records(Type, Records) ->
    case validate_build_records(Records) of
        ok ->
            Num = length(Records),
            message(Type, <<Num:8, (iolist_to_binary(Records))/binary>>);
        error ->
            error(badarg)
    end.

%% lookup_body/5 — the DatabaseLookup body shared by both builders: direct
%% replies omit the tunnel field, tunnel replies set the delivery flag (bit 0)
%% and place the 4-byte tunnel ID before the excluded list.
lookup_body(Key, From, LookupType, none, Excluded) ->
    <<Key/binary, From/binary, LookupType:8, (length(Excluded)):16/big,
        (iolist_to_binary(Excluded))/binary>>;
lookup_body(Key, From, LookupType, {ok, ReplyTunnelID}, Excluded) ->
    Flags = LookupType bor 16#01,
    <<Key/binary, From/binary, Flags:8, ReplyTunnelID:32/big, (length(Excluded)):16/big,
        (iolist_to_binary(Excluded))/binary>>.

%% Encode the DatabaseStore body. A nonzero reply token requires the reply
%% target tuple; a zero token omits both reply fields.
db_store_body(Key, StoreType, 0, _Reply, Data) ->
    <<Key/binary, StoreType:8, 0:32/big, Data/binary>>;
db_store_body(Key, StoreType, ReplyToken, {TunnelID, Gateway}, Data) when
    ReplyToken > 0, is_integer(TunnelID), is_binary(Gateway), byte_size(Gateway) =:= 32
->
    <<Key/binary, StoreType:8, ReplyToken:32/big, TunnelID:32/big, Gateway/binary, Data/binary>>;
db_store_body(_Key, _StoreType, ReplyToken, _Reply, _Data) when ReplyToken > 0 ->
    error(badarg).

%% Split the DatabaseLookup tail after the 65-byte fixed prefix
%% (key(32) ‖ from(32) ‖ flags(1)): an optional 4-byte tunnel ID when the
%% delivery flag is set, then `size(2) ‖ excluded(size*32)`, then any
%% reply-encryption bytes (reply key + tags) — preserved verbatim.
split_lookup_tail(Flags, <<TunnelID:32/big, R/binary>>) when Flags band 16#01 =:= 1 ->
    split_lookup_excluded(#{tunnel_id => TunnelID}, R, []);
split_lookup_tail(Flags, _Rest) when Flags band 16#01 =:= 1 ->
    error;
split_lookup_tail(_Flags, Rest) ->
    split_lookup_excluded(undefined, Rest, []).

split_lookup_excluded(Delivery, <<>>, Acc) ->
    {ok, Delivery, lists:reverse(Acc), <<>>};
split_lookup_excluded(Delivery, <<0:16/big, Encryption/binary>>, Acc) ->
    {ok, Delivery, lists:reverse(Acc), Encryption};
split_lookup_excluded(
    Delivery, <<Size:16/big, Peers:(Size * 32)/binary, Encryption/binary>>, Acc
) when
    Size =< ?MAX_EXCLUDED
->
    {ok, Delivery, lists:reverse(Acc) ++ split_hashes(Peers), Encryption};
split_lookup_excluded(_Delivery, _Rest, _Acc) ->
    error.

lookup_type_name(Flags) when Flags band 16#0C =:= ?LOOKUP_ANY -> any;
lookup_type_name(Flags) when Flags band 16#0C =:= ?LOOKUP_LEASESET -> leaseset;
lookup_type_name(Flags) when Flags band 16#0C =:= ?LOOKUP_ROUTERINFO -> routerinfo;
lookup_type_name(Flags) when Flags band 16#0C =:= ?LOOKUP_EXPLORATORY -> exploratory.

split_hashes(Bin) ->
    split_hashes(Bin, []).

split_hashes(<<>>, Acc) ->
    lists:reverse(Acc);
split_hashes(<<Hash:32/binary, Rest/binary>>, Acc) ->
    split_hashes(Rest, [Hash | Acc]).

deflate_raw(Bin) ->
    Z = zlib:open(),
    try
        ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
        Deflated = zlib:deflate(Z, Bin, finish),
        ok = zlib:deflateEnd(Z),
        iolist_to_binary(Deflated)
    after
        zlib:close(Z)
    end.

crc32(Bin) ->
    erlang:crc32(Bin).
