-module(i2p_netdb).

-moduledoc """
The Network Database (NetDb): a keyed store of RouterInfos plus the DHT
helpers a router needs to store and find network objects.

RouterInfos are keyed by their router hash (SHA-256 of the RouterIdentity) and
kept in a capacity-bounded LRU cache. Storing mirrors i2pd's
`NetDb::AddRouterInfo`: a RouterInfo with an equal or older publish timestamp
never replaces an existing one, one stamped too far in the future is rejected,
and one too old is rejected. A store is immutable; every operation returns a
new store, so the owning process (`m:i2p_netdb_srv`) can keep the shared state
without locks.

LeaseSets are stored alongside, keyed by their destination hash, in their own
capacity-bounded recency order. Storing mirrors i2pd's `NetDb::AddLeaseSet`:
an equal or older publish time never replaces an existing LeaseSet, and the
time-window checks from `m:i2p_leaset` `f:valid/2` reject one
published too far in the future or past its lifetime.

The DHT helpers follow i2pd's `IdentMetrics` / `NetDb`:

- **Routing key**: `SHA-256(routerHash ‖ yyyymmdd)` — the day-scoped key the
  XOR distance is computed over, so floodfill closeness varies by day.
- **XOR distance**: the byte-wise XOR of two routing keys, compared
  lexicographically (i2pd's `XORMetric`, `memcmp` over 32 bytes).
- **Floodfill eligibility**: version `>= 0.9.62` (`i2pd NETDB_MIN_FLOODFILL_VERSION`),
  router caps without `U`/`H`, and a published address — `published v4
  orelse (reachable v4 andalso published v6)` — matching
  `RouterInfo::IsEligibleFloodfill`. In 0.1.0 eligibility requires a published
  NTCP2 address; non-published NTCP2 addresses are ignored rather than treated
  as IPv6 endpoints.
- **Closest selection**: `f:closest/3` on routing-key distance,
  `f:closest_floodfills/4` restricted to eligible floodfills (the replication
  target set for a store), and `f:closest_non_floodfills/4` (the exploratory
  lookup set, mirroring `NetDb::GetExploratoryNonFloodfill`).

## Usage

```erlang
%% Build a store and fill it from DatabaseStore payloads.
Store0 = i2p_netdb:new(5000),
Now = erlang:system_time(millisecond),
{ok, Store1, added} = i2p_netdb:store_binary(Store0, RouterInfoBytes, Now),
{ok, Store2, updated} = i2p_netdb:store(Store1, RouterInfo, Now),

%% Find by router hash and pick replication targets.
Key = i2p_router_info:hash(RouterInfo),
{ok, RI} = i2p_netdb:find(Store2, Key),
Floodfills = i2p_netdb:closest_floodfills(Store2, Key, 3, []),
Exploratory = i2p_netdb:closest_non_floodfills(Store2, TargetKey, 3, []),

%% Store and find LeaseSets by destination hash.
DestHash = i2p_leaset:hash(LeaseSet),
{ok, Store3, added} = i2p_netdb:store_ls(Store2, LeaseSet, NowSec),
{ok, LeaseSet} = i2p_netdb:find_ls(Store3, DestHash),
```

The store is pure — the gen_server in `m:i2p_netdb_srv` owns a `store()`
process-local and answers queries against it.
""".

-export([
    new/0,
    new/1,
    store/3,
    store_binary/3,
    store_ls/3,
    store_ls_binary/3,
    find/2,
    find_ls/2,
    remove/2,
    routers/1,
    keys/1,
    ls_keys/1,
    ls_count/1,
    count/1,
    capacity/1,
    routing_key/1,
    routing_key/2,
    distance/2,
    closest/3,
    closest_floodfills/4,
    closest_non_floodfills/4,
    version_number/1,
    declared_floodfill/1,
    eligible_floodfill/1,
    is_ipv4/1,
    to_binary/1,
    from_binary/1,
    remove_expired/3
]).

-export_type([store/0, router_key/0, ls_key/0]).

-define(DEFAULT_CAPACITY, 5000).
%% i2pd NetDb.hpp: NETDB_MIN_FLOODFILL_VERSION = MAKE_VERSION_NUMBER(0, 9, 62).
-define(NETDB_MIN_FLOODFILL_VERSION, 962).
%% i2pd NetDb.cpp: reject RouterInfos stamped more than this into the future.
-define(EXPIRATION_THRESHOLD_MS, 2 * 60 * 1000).
%% i2pd NetDb.hpp: NETDB_MAX_EXPIRATION_TIMEOUT = 27 hours.
-define(MAX_EXPIRATION_MS, 27 * 60 * 60 * 1000).
-define(CAPS_FLOODFILL, $f).
-define(CAPS_UNREACHABLE, $U).
-define(CAPS_HIDDEN, $H).
-define(NTCP2_TRANSPORT, <<"NTCP2">>).
-define(VERSION, 1).

-doc "The NetDb key of a router: SHA-256 of its RouterIdentity.".
-type router_key() :: i2p_crypto:hash().

-doc "The NetDb key of a LeaseSet: SHA-256 of its destination identity.".
-type ls_key() :: i2p_crypto:hash().

-doc """
An immutable store: a map of router hash to RouterInfo plus the MRU-first
recency order used for capacity eviction, and a parallel map of destination
hash to LeaseSet with its own recency order.
""".
-opaque store() :: #{
    capacity := pos_integer(),
    routers := #{router_key() => i2p_router_info:router_info()},
    order := [router_key()],
    lease_sets := #{ls_key() => i2p_leaset:lease_set()},
    ls_order := [ls_key()]
}.

-doc "A fresh store with the default capacity (5000 routers).".
-spec new() -> store().
new() ->
    new(?DEFAULT_CAPACITY).

-doc """
A fresh store with a fixed `Capacity` — when a store would exceed it, the
least recently stored RouterInfo is evicted.
""".
-spec new(pos_integer()) -> store().
new(Capacity) when is_integer(Capacity), Capacity > 0 ->
    #{
        capacity => Capacity,
        routers => #{},
        order => [],
        lease_sets => #{},
        ls_order => []
    };
new(_) ->
    error(badarg).

-doc """
Store a verified RouterInfo.

Input: `Store` — the current store; `RI` — a parsed RouterInfo
(`m:i2p_router_info:decode/1`); `NowMs` — wall-clock ms since epoch.
Output: `{Store2, Outcome}`. `Outcome` is `added` for a new key, `updated`
when a strictly newer RouterInfo replaces an older one for the same key,
`older` when the existing entry is kept (equal or newer publish timestamp),
`from_future` / `too_old` when the timestamp fails i2pd's window checks (the
store is returned unchanged).
""".
-spec store(store(), i2p_router_info:router_info(), non_neg_integer()) ->
    {store(), added | updated | older | from_future | too_old}.
store(Store, RI, NowMs) when is_integer(NowMs) ->
    Key = i2p_router_info:hash(RI),
    case maps:find(Key, maps:get(routers, Store)) of
        {ok, Existing} ->
            case i2p_router_info:published(Existing) >= i2p_router_info:published(RI) of
                true -> {Store, older};
                false -> insert_newer(Store, Key, RI, NowMs, updated)
            end;
        error ->
            insert_newer(Store, Key, RI, NowMs, added)
    end;
store(_Store, _RI, _NowMs) ->
    error(badarg).

-doc """
Store a RouterInfo from its raw signed bytes.

Input: `Store` — the current store; `Bin` — full signed RouterInfo bytes;
`NowMs` — wall-clock ms since epoch.
Output: `{ok, Store2, Outcome}` as in `f:store/3`, or `{error, Reason}` when
the bytes do not decode to a signature-verifying RouterInfo
(`m:i2p_router_info:decode/1` reasons).
""".
-spec store_binary(store(), binary(), non_neg_integer()) ->
    {ok, store(), added | updated | older | from_future | too_old} | {error, term()}.
store_binary(Store, Bin, NowMs) ->
    case i2p_router_info:decode(Bin) of
        {ok, RI} ->
            {Store2, Outcome} = store(Store, RI, NowMs),
            {ok, Store2, Outcome};
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
Store a verified LeaseSet2.

Input: `Store` — the current store; `LS` — a parsed LeaseSet
(`m:i2p_leaset:decode/1`); `NowSec` — wall-clock seconds since epoch.
Output: `{Store2, Outcome}`. `Outcome` is `added` for a new key, `updated`
when a strictly newer LeaseSet replaces an older one for the same destination,
`older` when the existing entry is kept (equal or newer publish time),
`from_future` / `expired` when the publish time fails `m:i2p_leaset:valid/2`
(the store is returned unchanged). The same capacity bounds the LeaseSets, in
their own MRU order.
""".
-spec store_ls(store(), i2p_leaset:lease_set(), non_neg_integer()) ->
    {store(), added | updated | older | from_future | expired}.
store_ls(Store, LS, NowSec) when is_integer(NowSec) ->
    Key = i2p_leaset:hash(LS),
    case maps:find(Key, maps:get(lease_sets, Store)) of
        {ok, Existing} ->
            case i2p_leaset:published(Existing) >= i2p_leaset:published(LS) of
                true -> {Store, older};
                false -> insert_ls(Store, Key, LS, NowSec, updated)
            end;
        error ->
            insert_ls(Store, Key, LS, NowSec, added)
    end;
store_ls(_Store, _LS, _NowSec) ->
    error(badarg).

-doc """
Store a LeaseSet2 from its raw signed content bytes.

Input: `Store` — the current store; `Bin` — full signed LeaseSet2 content bytes
(without the DatabaseStore store-type byte); `NowSec` — wall-clock seconds
since epoch.
Output: `{ok, Store2, Outcome}` as in `f:store_ls/3`, or `{error, Reason}` when
the bytes do not decode to a signature-verifying LeaseSet2
(`m:i2p_leaset:decode/1` reasons).
""".
-spec store_ls_binary(store(), binary(), non_neg_integer()) ->
    {ok, store(), added | updated | older | from_future | expired} | {error, term()}.
store_ls_binary(Store, Bin, NowSec) ->
    case i2p_leaset:decode(Bin) of
        {ok, LS} ->
            {Store2, Outcome} = store_ls(Store, LS, NowSec),
            {ok, Store2, Outcome};
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
Look up a router by hash.

Input: `Store` — the store; `Key` — the router hash.
Output: `{ok, RI}` or `error` when absent. A read does not promote the entry
in the LRU order.
""".
-spec find(store(), router_key()) -> {ok, i2p_router_info:router_info()} | error.
find(Store, Key) ->
    maps:find(Key, maps:get(routers, Store)).

-doc """
Look up a LeaseSet by destination hash.

Input: `Store` — the store; `Key` — the destination hash.
Output: `{ok, LeaseSet}` or `error` when absent. A read does not promote the
entry in the recency order.
""".
-spec find_ls(store(), ls_key()) -> {ok, i2p_leaset:lease_set()} | error.
find_ls(Store, Key) ->
    maps:find(Key, maps:get(lease_sets, Store)).

-doc """
Remove a router by hash.

Input: `Store` — the store; `Key` — the router hash.
Output: `{Store2, removed}` when it was present, `{Store, not_found}` otherwise.
""".
-spec remove(store(), router_key()) -> {store(), removed | not_found}.
remove(Store, Key) ->
    Routers = maps:get(routers, Store),
    case maps:is_key(Key, Routers) of
        true ->
            {
                Store#{
                    routers := maps:remove(Key, Routers),
                    order := lists:delete(Key, maps:get(order, Store))
                },
                removed
            };
        false ->
            {Store, not_found}
    end.

-doc "All stored RouterInfos, in storage-recency order (MRU first).".
-spec routers(store()) -> [i2p_router_info:router_info()].
routers(Store) ->
    Routers = maps:get(routers, Store),
    [maps:get(K, Routers) || K <- maps:get(order, Store)].

-doc "All stored router hashes, in storage-recency order (MRU first).".
-spec keys(store()) -> [router_key()].
keys(Store) ->
    maps:get(order, Store).

-doc "The number of stored routers.".
-spec count(store()) -> non_neg_integer().
count(Store) ->
    map_size(maps:get(routers, Store)).

-doc "All stored destination hashes, in storage-recency order (MRU first).".
-spec ls_keys(store()) -> [ls_key()].
ls_keys(Store) ->
    maps:get(ls_order, Store).

-doc "The number of stored LeaseSets.".
-spec ls_count(store()) -> non_neg_integer().
ls_count(Store) ->
    map_size(maps:get(lease_sets, Store)).

-doc "The eviction capacity of the store.".
-spec capacity(store()) -> pos_integer().
capacity(Store) ->
    maps:get(capacity, Store).

-doc "The day-scoped routing key for the current UTC date: `SHA-256(Key ‖ yyyymmdd)`.".
-spec routing_key(router_key()) -> router_key().
routing_key(Key) ->
    routing_key(Key, current_day()).

-doc """
The day-scoped routing key for an explicit day.

Input: `Key` — the router hash; `Day` — 8 bytes, `yyyymmdd` in UTC.
Output: `SHA-256(Key ‖ Day)` — the value i2pd's `CreateRoutingKey` computes,
so XOR closeness between two routers varies by day.
""".
-spec routing_key(router_key(), binary()) -> router_key().
routing_key(Key, Day) when byte_size(Key) =:= 32, byte_size(Day) =:= 8 ->
    crypto:hash(sha256, <<Key/binary, Day/binary>>);
routing_key(_Key, _Day) ->
    error(badarg).

-doc """
The XOR distance between two router hashes.

Input: `Key1`, `Key2` — router hashes.
Output: the 32-byte XOR of their day-scoped routing keys. Two keys compare by
the lexicographic order of this value (i2pd's `XORMetric`); smaller is closer.
""".
-spec distance(router_key(), router_key()) -> binary().
distance(Key1, Key2) ->
    crypto:exor(routing_key(Key1), routing_key(Key2)).

-doc """
The `N` stored router hashes closest to `Target`.

Input: `Store` — the store; `Target` — the router hash to measure against;
`N` — how many to return.
Output: up to `N` hashes, sorted by routing-key XOR distance to `Target`,
closest first.
""".
-spec closest(store(), router_key(), non_neg_integer()) -> [router_key()].
closest(Store, Target, N) when is_integer(N), N >= 0 ->
    closest_keys(maps:keys(maps:get(routers, Store)), Target, N);
closest(_Store, _Target, _N) ->
    error(badarg).

-doc """
The `N` closest *eligible floodfill* hashes to `Target`, excluding `Excluded`.

Input: `Store`, `Target`, `N` as in `f:closest/3`; `Excluded` — a list of
hashes to skip (e.g. routers we already asked). Only routers that are both
declared (`caps` contains `f`) and eligible (`f:eligible_floodfill/1`) count —
this is the replication set i2pd picks (`GetClosestFloodfills(ident, 3, ...)`).
""".
-spec closest_floodfills(store(), router_key(), non_neg_integer(), [router_key()]) ->
    [router_key()].
closest_floodfills(Store, Target, N, Excluded) when
    is_integer(N), N >= 0, is_list(Excluded)
->
    Floodfills = [
        Key
     || Key <- maps:keys(maps:get(routers, Store)),
        not lists:member(Key, Excluded),
        is_eligible_floodfill(Store, Key)
    ],
    closest_keys(Floodfills, Target, N);
closest_floodfills(_Store, _Target, _N, _Excluded) ->
    error(badarg).

-doc """
The `N` closest *non-floodfill* hashes to `Target`, excluding `Excluded`.

Input: as in `f:closest_floodfills/4`. Routers that declare the floodfill cap
are skipped, mirroring i2pd's `GetExploratoryNonFloodfill` — the peer manager
uses this set to probe for routers close to a key without querying
floodfills.
""".
-spec closest_non_floodfills(store(), router_key(), non_neg_integer(), [router_key()]) ->
    [router_key()].
closest_non_floodfills(Store, Target, N, Excluded) when
    is_integer(N), N >= 0, is_list(Excluded)
->
    NonFloodfills = [
        Key
     || Key <- maps:keys(maps:get(routers, Store)),
        not lists:member(Key, Excluded),
        not declared_floodfill(maps:get(Key, maps:get(routers, Store)))
    ],
    closest_keys(NonFloodfills, Target, N);
closest_non_floodfills(_Store, _Target, _N, _Excluded) ->
    error(badarg).

-doc """
The numeric version of a RouterInfo.

Input: `RI` — a parsed RouterInfo.
Output: the `router.version` option's digits concatenated and read as an
integer (i2pd's `m_Version` parsing), e.g. `<<"0.9.74">>` → `974`,
`<<"0.9.62">>` → `962`. A missing or empty version yields `0`.
""".
-spec version_number(i2p_router_info:router_info()) -> non_neg_integer().
version_number(RI) ->
    Version = maps:get(<<"router.version">>, i2p_router_info:options(RI), <<>>),
    version_digits(Version, 0).

-doc """
Whether a RouterInfo declares the floodfill capability.

Input: `RI` — a parsed RouterInfo.
Output: `true` when its `caps` option contains `f` (i2pd's
`CAPS_FLAG_FLOODFILL`).
""".
-spec declared_floodfill(i2p_router_info:router_info()) -> boolean().
declared_floodfill(RI) ->
    binary:match(router_caps(RI), <<?CAPS_FLOODFILL>>) =/= nomatch.

-doc """
Whether a RouterInfo qualifies as a floodfill.

Input: `RI` — a parsed RouterInfo.
Output: `true` when it declares floodfill, is eligible: version
`>= 0.9.62`, router caps without `U`/`H`, and a published v4 address or
(reachable v4 and published v6). Mirrors i2pd's
`RouterInfo::IsEligibleFloodfill` narrowed to NTCP2-only transports; used to
decide whether a router joins the floodfill index.
""".
-spec eligible_floodfill(i2p_router_info:router_info()) -> boolean().
eligible_floodfill(RI) ->
    version_number(RI) >= ?NETDB_MIN_FLOODFILL_VERSION andalso
        not router_unreachable(RI) andalso
        (published_v4(RI) orelse (reachable_v4(RI) andalso published_v6(RI))).

-doc """
Whether a host string is an IPv4 literal.

Input: `Host` — e.g. `<<"192.0.2.10">>`.
Output: `true` for a valid dotted-quad IPv4, `false` otherwise (IPv6,
hostnames, malformed).
""".
-spec is_ipv4(binary()) -> boolean().
is_ipv4(Host) when is_binary(Host) ->
    case binary:split(Host, <<".">>, [global]) of
        [O1, O2, O3, O4] ->
            lists:all(fun is_octet/1, [O1, O2, O3, O4]);
        _ ->
            false
    end;
is_ipv4(_) ->
    false.

-doc """
Serialize the store to a binary.

Input: `Store` — a store.
Output: a binary encoding all stored RouterInfos and LeaseSets, preserving the
LRU order and capacity. Each RouterInfo and LeaseSet is encoded as raw signed
bytes via `m:i2p_router_info:to_binary/1` and `m:i2p_leaset:to_binary/1`. The
format is `<<"I2PNETDB">> ‖ version(1) ‖ capacity(4) ‖ router_count(4) ‖
entries ‖ ls_count(4) ‖ entries`.
""".
-spec to_binary(store()) -> binary().
to_binary(Store) ->
    Capacity = capacity(Store),
    RouterOrder = maps:get(order, Store),
    Routers = maps:get(routers, Store),
    RouterCount = length(RouterOrder),
    RouterBins = [router_entry(Key, Routers) || Key <- RouterOrder],
    LSOrder = maps:get(ls_order, Store),
    LSMaps = maps:get(lease_sets, Store),
    LSCount = length(LSOrder),
    LSBins = [ls_entry(Key, LSMaps) || Key <- LSOrder],
    <<"I2PNETDB", ?VERSION:8, Capacity:32/big, RouterCount:32/big,
        (iolist_to_binary(RouterBins))/binary, LSCount:32/big, (iolist_to_binary(LSBins))/binary>>.

-doc """
Deserialize a store from a binary produced by `f:to_binary/1`.

Input: `Bin` — the serialized store.
Output: `{ok, Store}` when the binary is well-formed and every RouterInfo /
LeaseSet signature verifies (`m:i2p_router_info:decode/1`,
`m:i2p_leaset:decode/1`); `{error, Reason}` otherwise. Entries with invalid
signatures or truncated bytes are silently dropped.
""".
-spec from_binary(binary()) -> {ok, store()} | {error, term()}.
from_binary(<<"I2PNETDB", ?VERSION:8, Rest/binary>>) ->
    maybe
        {ok, Capacity, RouterCount, AfterCount} ?= split_header(Rest),
        {ok, Routers, Order, AfterRouters} ?=
            parse_router_entries(AfterCount, RouterCount, #{}, []),
        {ok, LSCount, AfterLSCount} ?= split_ls_header(AfterRouters),
        {ok, LSMaps, LSOrder} ?= parse_ls_section(AfterLSCount, LSCount),
        {ok, #{
            capacity => Capacity,
            routers => Routers,
            order => lists:reverse(Order),
            lease_sets => LSMaps,
            ls_order => lists:reverse(LSOrder)
        }}
    else
        {error, _} = Err -> Err;
        error -> {error, malformed_router}
    end;
from_binary(_) ->
    {error, bad_magic}.

%% split_header/1 — the fixed-width store header preceding the router entries.
split_header(<<Capacity:32/big, RouterCount:32/big, AfterCount/binary>>) ->
    {ok, Capacity, RouterCount, AfterCount};
split_header(_) ->
    {error, truncated}.

%% split_ls_header/1 — the lease-set count separating routers from LS entries.
split_ls_header(<<LSCount:32/big, AfterLSCount/binary>>) ->
    {ok, LSCount, AfterLSCount};
split_ls_header(_) ->
    {error, truncated}.

%% parse_ls_section/2 — decode all lease-set entries; the section must be
%% consumed exactly.
parse_ls_section(Bin, Count) ->
    case parse_ls_entries(Bin, Count, #{}, []) of
        {ok, LSMaps, LSOrder, <<>>} -> {ok, LSMaps, LSOrder};
        {ok, _, _, _} -> {error, trailing_bytes};
        error -> {error, malformed_ls}
    end.

-doc """
Remove expired RouterInfos and LeaseSets.

Input: `Store` — the store; `NowMs` — wall-clock ms since epoch; `NowSec` —
wall-clock seconds since epoch.
Output: `{Store2, {RoutersRemoved, LSRemoved}}` where the counts reflect how
many entries were evicted. A RouterInfo is expired when its published timestamp
plus the 27-hour i2pd expiration threshold has fully passed. A LeaseSet is
expired when `m:i2p_leaset:valid/2` returns `{error, expired}`.
""".
-spec remove_expired(store(), non_neg_integer(), non_neg_integer()) ->
    {store(), {non_neg_integer(), non_neg_integer()}}.
remove_expired(Store, NowMs, NowSec) when is_integer(NowMs), is_integer(NowSec) ->
    Routers0 = maps:get(routers, Store),
    Order0 = maps:get(order, Store),
    {KeptRouters, KeptRouterOrder, RemovedRouters} = partition_routers(
        Routers0, Order0, NowMs, 0, []
    ),
    LeaseSets0 = maps:get(lease_sets, Store),
    LSOrder0 = maps:get(ls_order, Store),
    {KeptLS, KeptLSOrder, RemovedLS} = partition_ls(
        LeaseSets0, LSOrder0, NowSec, 0, []
    ),
    Store2 = Store#{
        routers => KeptRouters,
        order => lists:reverse(KeptRouterOrder),
        lease_sets => KeptLS,
        ls_order => lists:reverse(KeptLSOrder)
    },
    {Store2, {RemovedRouters, RemovedLS}};
remove_expired(_Store, _NowMs, _NowSec) ->
    error(badarg).

%%%%%%% %%% Internal %%%%%%%

is_octet(Octet) when byte_size(Octet) =< 3, byte_size(Octet) > 0 ->
    %% Stays a case: the scrutinee is an is_all_digits/1 call, not
    %% guard-expressible.
    case is_all_digits(Octet) of
        true -> binary_to_integer(Octet) =< 255;
        false -> false
    end;
is_octet(_) ->
    false.

is_all_digits(Bin) ->
    lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bin)).

insert_newer(Store, Key, RI, NowMs, Outcome) ->
    Timestamp = i2p_router_info:published(RI),
    case valid_window(Timestamp, NowMs) of
        true ->
            Routers0 = maps:get(routers, Store),
            Routers = Routers0#{Key => RI},
            Order0 = maps:get(order, Store),
            Order1 = [Key | lists:delete(Key, Order0)],
            {trim(Store#{routers => Routers, order => Order1}), Outcome};
        false ->
            {Store, outcome_for_window(Timestamp, NowMs)}
    end.

%% i2pd NetDb.cpp AddRouterInfo: reject from future (now + 2 min) and too old
%% (now > timestamp + 27 h).
valid_window(Timestamp, NowMs) ->
    Timestamp =< NowMs + ?EXPIRATION_THRESHOLD_MS andalso
        NowMs =< Timestamp + ?MAX_EXPIRATION_MS.

%% Insert a LeaseSet after the equal-or-newer check; the i2p_leaset:valid/2
%% window decides acceptance.
insert_ls(Store, Key, LS, NowSec, Outcome) ->
    case i2p_leaset:valid(LS, NowSec) of
        ok ->
            LeaseSets0 = maps:get(lease_sets, Store),
            LeaseSets = LeaseSets0#{Key => LS},
            Order0 = maps:get(ls_order, Store),
            Order1 = [Key | lists:delete(Key, Order0)],
            {trim_ls(Store#{lease_sets => LeaseSets, ls_order => Order1}), Outcome};
        {error, from_future} ->
            {Store, from_future};
        {error, expired} ->
            {Store, expired}
    end.

outcome_for_window(Timestamp, NowMs) when Timestamp > NowMs + ?EXPIRATION_THRESHOLD_MS ->
    from_future;
outcome_for_window(_Timestamp, _NowMs) ->
    too_old.

trim(Store) ->
    Order = maps:get(order, Store),
    case length(Order) > maps:get(capacity, Store) of
        true ->
            [Evicted | Rest] = lists:reverse(Order),
            Store#{
                routers := maps:remove(Evicted, maps:get(routers, Store)),
                order := lists:reverse(Rest)
            };
        false ->
            Store
    end.

%% Evict the least recently stored LeaseSet when the capacity is exceeded
%% (the LeaseSets share the router store's capacity bound).
trim_ls(Store) ->
    Order = maps:get(ls_order, Store),
    case length(Order) > maps:get(capacity, Store) of
        true ->
            [Evicted | Rest] = lists:reverse(Order),
            Store#{
                lease_sets := maps:remove(Evicted, maps:get(lease_sets, Store)),
                ls_order := lists:reverse(Rest)
            };
        false ->
            Store
    end.

closest_keys(Keys, Target, N) ->
    TargetKey = routing_key(Target),
    Sorted = lists:sort(
        fun(K1, K2) ->
            crypto:exor(routing_key(K1), TargetKey) < crypto:exor(routing_key(K2), TargetKey)
        end,
        Keys
    ),
    lists:sublist(Sorted, N).

is_eligible_floodfill(Store, Key) ->
    RI = maps:get(Key, maps:get(routers, Store)),
    declared_floodfill(RI) andalso eligible_floodfill(RI).

router_caps(RI) ->
    maps:get(<<"caps">>, i2p_router_info:options(RI), <<>>).

router_unreachable(RI) ->
    Caps = router_caps(RI),
    contains_any(Caps, [?CAPS_UNREACHABLE, ?CAPS_HIDDEN]).

published_v4(RI) ->
    lists:any(fun published_v4_addr/1, published_ntcp2_addresses(RI)).

published_v6(RI) ->
    lists:any(fun published_v6_addr/1, published_ntcp2_addresses(RI)).

reachable_v4(RI) ->
    lists:any(fun is_v4_addr/1, ntcp2_addresses(RI)).

published_ntcp2_addresses(RI) ->
    [
        Addr
     || Addr <- ntcp2_addresses(RI),
        maps:is_key(<<"host">>, maps:get(options, Addr)),
        not addr_unreachable(Addr)
    ].

ntcp2_addresses(RI) ->
    [
        Addr
     || Addr <- i2p_router_info:addresses(RI),
        maps:get(transport, Addr) =:= ?NTCP2_TRANSPORT
    ].

published_v4_addr(Addr) ->
    is_ipv4(host_of(Addr)).

published_v6_addr(Addr) ->
    not is_ipv4(host_of(Addr)).

is_v4_addr(Addr) ->
    is_ipv4(host_of(Addr)).

host_of(Addr) ->
    maps:get(<<"host">>, maps:get(options, Addr), undefined).

addr_unreachable(Addr) ->
    Caps = maps:get(<<"caps">>, maps:get(options, Addr), <<>>),
    contains_any(Caps, [?CAPS_UNREACHABLE, ?CAPS_HIDDEN]).

contains_any(Caps, Chars) ->
    lists:any(fun(C) -> binary:match(Caps, <<C>>) =/= nomatch end, Chars).

version_digits(<<C, Rest/binary>>, Acc) when C >= $0, C =< $9 ->
    version_digits(Rest, Acc * 10 + (C - $0));
version_digits(<<_, Rest/binary>>, Acc) ->
    version_digits(Rest, Acc);
version_digits(<<>>, Acc) ->
    Acc.

current_day() ->
    {{Y, M, D}, _} = calendar:universal_time(),
    iolist_to_binary(io_lib:format("~4..0B~2..0B~2..0B", [Y, M, D])).

%% ---- to_binary helpers ----

router_entry(Key, Routers) ->
    RI = maps:get(Key, Routers),
    Bin = i2p_router_info:to_binary(RI),
    <<Key/binary, (byte_size(Bin)):16/big, Bin/binary>>.

ls_entry(Key, LSMaps) ->
    LS = maps:get(Key, LSMaps),
    Bin = i2p_leaset:to_binary(LS),
    <<Key/binary, (byte_size(Bin)):16/big, Bin/binary>>.

%% ---- from_binary helpers ----

parse_router_entries(Bin, 0, Routers, Order) ->
    {ok, Routers, Order, Bin};
parse_router_entries(<<>>, _Count, _Routers, _Order) ->
    error;
parse_router_entries(
    <<Key:32/binary, Len:16/big, RIBin:Len/binary, Rest/binary>>, Count, Routers, Order
) ->
    case i2p_router_info:decode(RIBin) of
        {ok, RI} ->
            parse_router_entries(
                Rest,
                Count - 1,
                Routers#{Key => RI},
                [Key | Order]
            );
        {error, _} ->
            parse_router_entries(Rest, Count - 1, Routers, Order)
    end;
parse_router_entries(_, _, _, _) ->
    error.

parse_ls_entries(Bin, 0, LSMaps, LSOrder) ->
    {ok, LSMaps, LSOrder, Bin};
parse_ls_entries(<<>>, _Count, _LSMaps, _LSOrder) ->
    error;
parse_ls_entries(
    <<Key:32/binary, Len:16/big, LSBin:Len/binary, Rest/binary>>, Count, LSMaps, LSOrder
) ->
    case i2p_leaset:decode(LSBin) of
        {ok, LS} ->
            parse_ls_entries(
                Rest,
                Count - 1,
                LSMaps#{Key => LS},
                [Key | LSOrder]
            );
        {error, _} ->
            parse_ls_entries(Rest, Count - 1, LSMaps, LSOrder)
    end;
parse_ls_entries(_, _, _, _) ->
    error.

%% ---- remove_expired helpers ----

partition_routers(_Routers, [], _NowMs, Removed, Kept) ->
    {maps:from_list(Kept), Kept, Removed};
partition_routers(Routers, [Key | Rest], NowMs, Removed, Kept) ->
    RI = maps:get(Key, Routers),
    Published = i2p_router_info:published(RI),
    case Published + ?MAX_EXPIRATION_MS < NowMs of
        true ->
            partition_routers(Routers, Rest, NowMs, Removed + 1, Kept);
        false ->
            partition_routers(Routers, Rest, NowMs, Removed, [{Key, RI} | Kept])
    end.

partition_ls(_LSMaps, [], _NowSec, Removed, Kept) ->
    {maps:from_list(Kept), Kept, Removed};
partition_ls(LSMaps, [Key | Rest], NowSec, Removed, Kept) ->
    LS = maps:get(Key, LSMaps),
    case i2p_leaset:valid(LS, NowSec) of
        {error, expired} ->
            partition_ls(LSMaps, Rest, NowSec, Removed + 1, Kept);
        _ ->
            partition_ls(LSMaps, Rest, NowSec, Removed, [{Key, LS} | Kept])
    end.
