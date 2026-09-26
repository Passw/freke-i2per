-module(i2p_status_data).

-moduledoc """
Read-only status aggregation for external observers.

One function, `f:view/0`, gathering the router's introspection APIs into a
plain data map. It exists so remote processes (the `i2per_status` web
service on another node) can fetch a complete snapshot with a single
`erpc:call(Node, ?MODULE, view, [], Timeout)` — every module it touches is
guaranteed present wherever the router runs.
""".

-export([view/0, aggregate_peers/1]).

-doc """
Aggregate router status.

Output: a map with our identity (base64 destination-style hash encoding of
the router hash), peer/tunnel/netdb/SAM-session counters. Read-only; safe to
call from any process on any connected node via `erpc`.
""".
-spec view() ->
    #{
        identity := binary(),
        peers := #{connected => non_neg_integer(), other => non_neg_integer()},
        tunnels :=
            #{
                outbound := non_neg_integer(),
                inbound := non_neg_integer(),
                transit := non_neg_integer(),
                pending := non_neg_integer(),
                exploratory_outbound := non_neg_integer(),
                exploratory_inbound := non_neg_integer()
            },
        netdb := #{ri := non_neg_integer(), ls := non_neg_integer()},
        sessions := non_neg_integer()
    }.
view() ->
    Tunnels = i2p_tunnel_srv:status(),
    #{
        identity => identity_b64(i2p_peer:router_hash()),
        peers => aggregate_peers(i2p_peer:status()),
        tunnels => #{
            outbound => map_size(maps:get(tunnels, Tunnels)),
            inbound => map_size(maps:get(inbound, Tunnels)),
            transit => map_size(maps:get(transit, Tunnels)),
            pending =>
                map_size(maps:get(pending, Tunnels)) + map_size(maps:get(pending_in, Tunnels)),
            exploratory_outbound =>
                map_size(maps:get(exploratory, Tunnels, #{})),
            exploratory_inbound =>
                map_size(maps:get(exploratory_in, Tunnels, #{}))
        },
        netdb => #{ri => i2p_netdb_srv:count(), ls => i2p_netdb_srv:ls_count()},
        sessions => length(i2p_sam_sup:client_sessions())
    }.

%% identity_b64/1 — standard base64 of the 32-byte hash (display only).
identity_b64(Hash) when byte_size(Hash) =:= 32 ->
    base64:encode(Hash).

%% aggregate_peers/1 — collapse per-peer states into two buckets.
%% Exported so the pure aggregation can be unit-tested without a live router.
-doc """
Collapse the map returned by `f:i2p_peer:status/0` into
`#{connected, other}` counters.

Input: the peer-status map as returned by `i2p_peer:status/0`. Only peers
whose status map says `connected` count as connected; everything else — idle,
failed, excluded — lands in `other`.
""".
-spec aggregate_peers(map()) -> #{connected => non_neg_integer(), other => non_neg_integer()}.
aggregate_peers(PeerStatus) ->
    lists:foldl(
        fun
            (#{status := connected}, Acc) ->
                maps:update_with(connected, fun(N) -> N + 1 end, 1, Acc);
            (_, Acc) ->
                maps:update_with(other, fun(N) -> N + 1 end, 1, Acc)
        end,
        #{connected => 0, other => 0},
        maps:values(PeerStatus)
    ).
