%% Per-peer reliability tests. The suite covers counters, avoidance decisions,
%% decay, status reporting, persistence, and calls made without a running
%% server. Cases that start the service use a temporary data directory, so no
%% global application state leaks between cases.
%% Decay and persistence cases manage their own server lifecycle; the other
%% server-backed cases use the instance started by `init_per_testcase`. The
%% decay window is supplied by a hand-written table, so no fixed sleep controls
%% the result.

-module(i2p_peer_rep_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    absent_server_noops/1,
    unknown_peer_not_avoided/1,
    below_threshold_not_avoided/1,
    successes_balance_failures/1,
    protected_peer_never_avoided/1,
    status_reports_avoidance/1,
    decay_forgives_old_failures/1,
    persistence_roundtrip/1
]).

-include_lib("eunit/include/eunit.hrl").

-define(APP, i2per).
-define(REP_FILE, "peer_rep.bin").
-define(FILE_HEADER, "I2PREP").
-define(FILE_VERSION, 1).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        absent_server_noops,
        unknown_peer_not_avoided,
        below_threshold_not_avoided,
        successes_balance_failures,
        protected_peer_never_avoided,
        status_reports_avoidance,
        decay_forgives_old_failures,
        persistence_roundtrip
    ].

%% Every case gets a fresh, isolated `data_dir` beneath the CT priv dir, set as
%% app env before any server starts so load_table sees it. The five plain cases
%% also get a fresh server in init; absent_server_noops must start with none,
%% and decay/persistence manage their own start/stop (decay writes the file
%% first, persistence restarts mid-case).
init_per_testcase(Case, Config) ->
    case Case of
        absent_server_noops ->
            Config;
        decay_forgives_old_failures ->
            ok = application:set_env(?APP, data_dir, i2p_ct_helpers:temp_data_dir(Config)),
            Config;
        persistence_roundtrip ->
            ok = application:set_env(?APP, data_dir, i2p_ct_helpers:temp_data_dir(Config)),
            Config;
        _ ->
            ok = application:set_env(?APP, data_dir, i2p_ct_helpers:temp_data_dir(Config)),
            {ok, _} = i2p_peer_rep:start_link(),
            Config
    end.

end_per_testcase(absent_server_noops, _Config) ->
    ok;
end_per_testcase(_Case, _Config) ->
    stop_if_running(),
    ok = application:unset_env(?APP, data_dir),
    ok.

%% --------------------------------------------------------------------------
%% The signal API and the avoidance query are safe with no server running:
%% emitters never crash over telemetry, and selection falls back to
%% distance-only.
%% --------------------------------------------------------------------------

absent_server_noops(_Config) ->
    Hash = rand_hash(),
    ?assertEqual(ok, i2p_peer_rep:connected(Hash)),
    ?assertEqual(ok, i2p_peer_rep:connect_failed(Hash)),
    ?assertEqual(ok, i2p_peer_rep:protect(Hash)),
    ?assertEqual(false, i2p_peer_rep:avoided(Hash)).

unknown_peer_not_avoided(_Config) ->
    ?assertEqual(false, i2p_peer_rep:avoided(rand_hash())).

%% The avoidance rule needs `?FAIL_THRESHOLD` failures with failures
%% outnumbering successes; two failures must not blacklist a peer.
below_threshold_not_avoided(_Config) ->
    Hash = rand_hash(),
    ?assertEqual(ok, i2p_peer_rep:connect_failed(Hash)),
    ?assertEqual(ok, i2p_peer_rep:connect_failed(Hash)),
    ?assertEqual(false, i2p_peer_rep:avoided(Hash)),
    ?assertEqual(ok, i2p_peer_rep:connect_failed(Hash)),
    ?assertEqual(true, i2p_peer_rep:avoided(Hash)),
    #{Hash := Rep} = i2p_peer_rep:snapshot(),
    ?assertEqual(3, maps:get(fail, Rep)).

%% A peer that fails as often as it succeeds is flaky, not reliably bad:
%% `fail > ok` must not hold, so it stays selectable.
successes_balance_failures(_Config) ->
    Hash = rand_hash(),
    lists:foreach(fun(_) -> i2p_peer_rep:connect_failed(Hash) end, lists:seq(1, 3)),
    ?assertEqual(true, i2p_peer_rep:avoided(Hash)),
    lists:foreach(fun(_) -> i2p_peer_rep:connected(Hash) end, lists:seq(1, 3)),
    ?assertEqual(false, i2p_peer_rep:avoided(Hash)).

%% `protect/1` exempts a peer from avoidance no matter how bad the record is.
protected_peer_never_avoided(_Config) ->
    Hash = rand_hash(),
    lists:foreach(fun(_) -> i2p_peer_rep:connect_failed(Hash) end, lists:seq(1, 4)),
    ?assertEqual(true, i2p_peer_rep:avoided(Hash)),
    ?assertEqual(ok, i2p_peer_rep:protect(Hash)),
    ?assertEqual(false, i2p_peer_rep:avoided(Hash)).

%% status/0 exposes the lifetime counters plus the live avoidance verdict.
status_reports_avoidance(_Config) ->
    Bad = rand_hash(),
    Good = rand_hash(),
    lists:foreach(fun(_) -> i2p_peer_rep:connect_failed(Bad) end, lists:seq(1, 3)),
    i2p_peer_rep:connected(Good),
    Status = i2p_peer_rep:status(),
    #{Bad := BadRep, Good := GoodRep} = Status,
    ?assertMatch(#{ok := 0, fail := 3, avoided := true}, BadRep),
    ?assertMatch(#{ok := 1, fail := 0, avoided := false}, GoodRep).

%% Failures inside the avoidance window blacklist a peer, but the same record
%% with a `last_fail` far in the past loads as selectable again: old failures
%% decay. The decayed table is written by hand so the test can control the
%% timestamp without a clock dependency — the on-disk format matches
%% i2p_peer_rep:encode/1 exactly, so the server's load path decodes it.
decay_forgives_old_failures(_Config) ->
    Dir = data_dir(),
    Now = erlang:system_time(second),
    Fresh = rand_hash(),
    Old = rand_hash(),
    OldSeconds = Now - 2 * 86400,
    Table = #{
        Fresh => #{ok => 0, fail => 3, last_ok => 0, last_fail => Now},
        Old => #{ok => 0, fail => 3, last_ok => 0, last_fail => OldSeconds}
    },
    Bin = <<?FILE_HEADER, ?FILE_VERSION:8, (term_to_binary(Table))/binary>>,
    ok = file:write_file(filename:join(Dir, ?REP_FILE), Bin),
    {ok, _} = i2p_peer_rep:start_link(),
    ?assertEqual(true, i2p_peer_rep:avoided(Fresh)),
    ?assertEqual(false, i2p_peer_rep:avoided(Old)).

%% Records survive a server restart via `save/0` + load-on-init, mirroring the
%% NetDb persistence contract.
persistence_roundtrip(_Config) ->
    {ok, Pid} = i2p_peer_rep:start_link(),
    try
        Bad = rand_hash(),
        Good = rand_hash(),
        lists:foreach(fun(_) -> i2p_peer_rep:connect_failed(Bad) end, lists:seq(1, 3)),
        i2p_peer_rep:connected(Good),
        ?assertEqual(ok, i2p_peer_rep:save()),
        kill_and_wait(Pid),
        {ok, _Pid2} = i2p_peer_rep:start_link(),
        try
            Snap = i2p_peer_rep:snapshot(),
            #{Bad := BadRep, Good := GoodRep} = Snap,
            ?assertEqual(3, maps:get(fail, BadRep)),
            ?assertEqual(0, maps:get(ok, BadRep)),
            ?assertEqual(1, maps:get(ok, GoodRep)),
            ?assertEqual(true, i2p_peer_rep:avoided(Bad)),
            ?assertEqual(false, i2p_peer_rep:avoided(Good))
        after
            stop_if_running()
        end
    after
        stop_if_running()
    end.

%% --------------------------------------------------------------------------
%% Helpers
%% --------------------------------------------------------------------------

data_dir() ->
    {ok, Dir} = application:get_env(?APP, data_dir),
    Dir.

stop_if_running() ->
    case whereis(i2p_peer_rep) of
        undefined ->
            ok;
        Pid ->
            Ref = erlang:monitor(process, Pid),
            unlink(Pid),
            exit(Pid, shutdown),
            receive
                {'DOWN', Ref, process, Pid, _} -> ok
            after 2000 ->
                erlang:error({stop_timeout, Pid})
            end
    end.

kill_and_wait(Pid) ->
    Ref = erlang:monitor(process, Pid),
    unlink(Pid),
    exit(Pid, shutdown),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 2000 ->
        erlang:error({kill_timeout, Pid})
    end.

rand_hash() ->
    crypto:strong_rand_bytes(32).
