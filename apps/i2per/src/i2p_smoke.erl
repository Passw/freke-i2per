-module(i2p_smoke).

-moduledoc """
Live-network smoke observability without touching the data path.

This module powers `scripts/live_smoke.escript`, the on-demand (never in
`just check`) network join test. It boots the router, runs a fixed window, and
reports the observables that tell an operator whether the instance is really
on the network:

* `peers` — non-self outbound peers connected at the end of the window, from
  `f:i2p_peer:status/0`.
* `dialed` — live inbound sessions accepted by the boot listeners, from
  `f:i2p_peer:dialed/0` (other routers dialed *us*).
* `netdb_router_info_growth` — local NetDb router-info count growth after the
  live reseed pass has completed, measured with `f:i2p_netdb_srv:count/0`
  before and after the observation window. This is a local store-growth
  signal, not proof of remote floodfill acceptance; the reseed bundle itself
  is deliberately outside the delta.
* `floodfill_store_accepts` — deprecated compatibility alias for
  `netdb_router_info_growth`; it has the same local-count meaning.
* `transit_relayed_tunnels` — transit tunnel count at the end of the window,
  from `f:i2p_tunnel_srv:status/0` (tunnels built purely through us, which a
  NATed router genuinely cannot produce without a public address).

Nothing here touches a per-message hot path: all four observables are derived
from the existing introspection APIs, one gen-server/ETS read each per report.

Hermetic self-dial mode (`live => false`, the default from
`scripts/live_smoke.escript`) feeds the router *its own* RouterInfo as the
sole seed and fires the boot floodfill-discovery kick at t=0, so the peer
manager dials our published NTCP2 listener as if it were an external Alice —
which lands back in `i2p_peer`'s inbound-session map. Live mode (`live => true`)
starts with no self seed, enables the reseed worker, and waits for that pass
to finish before measuring lookup-driven NetDb growth. The operator's network
must actually be reachable for remote peers to appear.
""".

-export([report/1]).

-export_type([opts/0]).

-type opts() :: #{
    window_ms := pos_integer(),
    data_dir := file:filename_all(),
    port := inet:port_number(),
    live => boolean(),
    host => binary(),
    reseed => term()
}.

-doc """
Run one smoke window.

Input: `Opts` — `window_ms` (how long to observe), `data_dir` (temp identity
dir), `port` (local NTCP2 port), `live` (reseed the real network when
`true`; see the module doc for the hermetic default), `host` (listening
address, default `<<"127.0.0.1">>`).

Output: the smoke report as a JSON map, one field per observable.
""".
-spec report(opts()) -> map().
report(Opts) ->
    WindowMs = maps:get(window_ms, Opts),
    Dir = maps:get(data_dir, Opts),
    Port = maps:get(port, Opts),
    Host = maps:get(host, Opts, <<"127.0.0.1">>),
    Live = maps:get(live, Opts, false),
    {ok, Id} = i2p_identity:ensure_identity(Dir),
    _ = application:load(i2per),
    ok = application:set_env(i2per, ntcp2_published, Live =:= false),
    Local = i2p_identity:build_local(Id, Host, Port, maps:get(sign_seed, Id)),
    Reseed =
        case Live of
            true -> maps:get(reseed, Opts, #{enabled => true, min_routers => 1});
            false -> #{enabled => false}
        end,
    Seeds =
        case Live of
            true -> [];
            false -> [maps:get(ri, Local)]
        end,
    ok = application:set_env(i2per, data_dir, Dir),
    ok = application:set_env(i2per, seeds, Seeds),
    ok = application:set_env(i2per, host, Host),
    ok = application:set_env(i2per, port, Port),
    ok = application:set_env(i2per, allow_private_host, true),
    ok = application:set_env(i2per, reseed, Reseed),
    ok = application:set_env(i2per, live_network, Live),
    ok =
        case Live of
            true ->
                application:set_env(
                    i2per,
                    floodfill_discovery_delay_ms,
                    maps:get(
                        discovery_kick_ms, Opts, 100
                    )
                );
            false ->
                application:set_env(i2per, floodfill_discovery_delay_ms, 0)
        end,
    {ok, _} = application:ensure_all_started(i2per),
    try
        ok = await_reseed(Live),
        Ri0 = i2p_netdb_srv:count(),
        timer:sleep(WindowMs),
        Ri1 = i2p_netdb_srv:count(),
        Trans = i2p_tunnel_srv:status(),
        OwnHash = i2p_peer:router_hash(),
        Status = i2p_peer:status(),
        Growth = erlang:max(0, Ri1 - Ri0),
        #{
            <<"window_ms">> => WindowMs,
            <<"peers">> => connected_count(OwnHash, Status),
            <<"dialed">> => i2p_peer:dialed(),
            <<"netdb_router_info_growth">> => Growth,
            <<"floodfill_store_accepts">> => Growth,
            <<"transit_relayed_tunnels">> => map_size(maps:get(transit, Trans, #{}))
        }
    after
        ok = application:stop(i2per)
    end.

await_reseed(false) ->
    ok;
await_reseed(true) ->
    await_reseed_worker(300).

await_reseed_worker(0) ->
    ok;
await_reseed_worker(Attempts) ->
    case whereis(i2p_reseed_srv) of
        undefined ->
            ok;
        _Pid ->
            timer:sleep(100),
            await_reseed_worker(Attempts - 1)
    end.

connected_count(OwnHash, Status) ->
    maps:fold(
        fun
            (Hash, Ps, Acc) when Hash =/= OwnHash ->
                case maps:get(status, Ps, none) of
                    connected -> Acc + 1;
                    _ -> Acc
                end;
            (_Hash, _Ps, Acc) ->
                Acc
        end,
        0,
        Status
    ).
