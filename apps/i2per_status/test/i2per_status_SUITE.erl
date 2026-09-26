%% Distributed status-service tests. The Common Test node is started with a
%% fixed distribution name by the `just ct` recipes, so the suite never calls
%% `net_kernel:start` or spawns `epmd` itself. A peer router is started for the
%% `dist` group, and the status service talks to it over erpc. Readiness polls
%% use deadline-bounded helpers.

-module(i2per_status_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([
    dist_snapshot_matches_remote_identity/1,
    dist_realtime_bus_counter_over_erpc/1
]).

-define(SUITE_TIMEOUT, 90000).

all() ->
    [{group, dist}].

groups() ->
    [
        {dist, [sequence], [
            dist_snapshot_matches_remote_identity,
            dist_realtime_bus_counter_over_erpc
        ]}
    ].

suite() ->
    [{timetrap, ?SUITE_TIMEOUT}].

%% This suite only makes sense on a dist-enabled node (it spawns a second VM
%% via `peer` and talks to it over erpc). rebar3 starts the CT run node with
%% `-sname` when invoked with `--sname i2per_ct` (every recipe in the justfile
%% passes it). Fail loudly instead of letting `peer` fail cryptically.
init_per_suite(Config) ->
    assert_distributed(node()),
    _ = application:stop(i2per_status),
    Config.

end_per_suite(_Config) ->
    ok.

%% One shared router VM for both cases: booting it is the expensive part, and
%% the second case reuses the already-online router for the realtime counter.
%% `peer:start`, NOT `peer:start_link`: CT runs init_per_group in a short-lived
%% process that exits before the first testcase, and a linked peer would die
%% with it. `peer:stop/1` in end_per_group still works from any process
%% (plain `gen_server:stop/2`).
init_per_group(dist, Config) ->
    {ok, RouterPid, RNode} =
        peer:start(#{
            %% No `host`: an IP would leak dots into a -sname and break it.
            name => i2per_status_dist_router,
            args => ["-pa", ebin_dir()],
            wait_boot => 30_000
        }),
    boot_remote_router(RNode),
    [{router, {RouterPid, RNode}} | Config].

end_per_group(dist, Config) ->
    {RouterPid, _RNode} = proplists:get_value(router, Config),
    peer:stop(RouterPid),
    ok.

%% The status service reports online once the remote router is reachable, and
%% the reported identity is the remote router's hash, base64-encoded.
dist_snapshot_matches_remote_identity(Config) ->
    RNode = router_node(Config),
    start_status(RNode),
    try
        ok = i2p_ct_helpers:await(
            fun() -> maps:get(online, i2per_status_state:snapshot()) end,
            15000
        ),
        Snap = i2per_status_state:snapshot(),
        ?assertEqual(true, maps:get(online, Snap)),
        %% Identity reported over erpc matches the remote router.
        RemoteHash = erpc:call(RNode, i2p_peer, router_hash, [], 5000),
        ?assertEqual(base64:encode(RemoteHash), maps:get(identity, Snap))
    after
        application:stop(i2per_status)
    end.

%% Realtime: announce on the REMOTE bus, count locally.
dist_realtime_bus_counter_over_erpc(Config) ->
    RNode = router_node(Config),
    start_status(RNode),
    try
        ok = i2p_ct_helpers:await(
            fun() -> maps:get(online, i2per_status_state:snapshot()) end,
            15000
        ),
        Before = tunnel_built_count(i2per_status_state:snapshot()),
        ok = erpc:call(RNode, i2p_events, notify, [{tunnel_built, outbound, 2}], 5000),
        ok = i2p_ct_helpers:await(
            fun() -> tunnel_built_count(i2per_status_state:snapshot()) >= Before + 1 end,
            20000
        )
    after
        application:stop(i2per_status)
    end.

%% %%%%% %%% Internal helpers %%%%% %%%

assert_distributed(nonode@nohost) ->
    ct:fail(
        "i2per_status_SUITE needs a dist-enabled CT run node; "
        "run `rebar3 ct --sname i2per_ct` (see the justfile recipes)."
    );
assert_distributed(_Node) ->
    ok.

router_node(Config) ->
    {_RouterPid, RNode} = proplists:get_value(router, Config),
    RNode.

start_status(RNode) ->
    application:set_env(i2per_status, port, i2p_ct_helpers:free_port()),
    application:set_env(i2per_status, router_node, RNode),
    {ok, _} = application:ensure_all_started(i2per_status),
    ok.

%% Boot exactly what `m:i2p_status_data:view/0` reads on the remote router:
%% the whole `i2per` app, which owns i2p_peer and the bus. NEVER start_link
%% router pieces over plain erpc: the call's transient worker on the remote
%% node would be their parent and kill them on return. Instead configure the
%% app env and let the REMOTE supervisor own the processes.
boot_remote_router(RNode) ->
    {Pub, Priv} = erpc:call(RNode, i2p_crypto, x25519_keygen, [], 5000),
    {SignPub, Seed} = erpc:call(RNode, i2p_crypto, ed25519_keygen, [], 5000),
    Id = erpc:call(RNode, i2p_keys, from_keys, [Pub, SignPub], 5000),
    IV = crypto:strong_rand_bytes(16),
    Addr =
        erpc:call(
            RNode,
            i2p_router_info,
            ntcp2_address,
            [<<"127.0.0.1">>, 39901, Pub, IV],
            5000
        ),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI =
        erpc:call(
            RNode, i2p_router_info, build, [Id, now_ms(), [Addr], Opts, Seed], 5000
        ),
    Hash = erpc:call(RNode, i2p_router_info, hash, [RI], 5000),
    Local = #{
        static_priv => Priv,
        static_pub => Pub,
        hash => Hash,
        iv => IV,
        ri => RI
    },
    ok = erpc:call(
        RNode, application, set_env, [i2per, i2p_peer, #{local => Local, seeds => []}], 5000
    ),
    {ok, _} =
        erpc:call(RNode, application, ensure_all_started, [i2per], 15_000),
    ok.

ebin_dir() ->
    %% Anchor on THIS suite's beam directory — never trust the process cwd.
    BeamDir = filename:dirname(code:which(?MODULE)),
    RepoRoot = filename:join(BeamDir, "../../.."),
    case filelib:is_dir(filename:join(RepoRoot, "_build/test/lib/i2per/ebin")) of
        true -> filename:join(RepoRoot, "_build/test/lib/i2per/ebin");
        false -> filename:join(BeamDir, "../../../lib/i2per/ebin")
    end.

now_ms() ->
    erlang:system_time(millisecond).

tunnel_built_count(Snap) ->
    case maps:find(events, Snap) of
        {ok, Ev} -> maps:get(tunnel_built, Ev, 0);
        error -> 0
    end.
