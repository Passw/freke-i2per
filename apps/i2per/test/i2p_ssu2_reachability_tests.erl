-module(i2p_ssu2_reachability_tests).

-moduledoc """
Tests for the `m:i2p_ssu2_reachability` decision: the private-host boot rule
and the `peertest_result` → `{reachability, ssu2, Status}` transitions.

The app is (re)started under each configured `allow_private_host` value and
torn down afterwards so the explicit test mode (no peer, no listeners) never
binds anything; the events bus is the router's own.
""".

-include_lib("eunit/include/eunit.hrl").

%% A loopback/private-host boot is firewalled by construction: it cannot accept
%% inbound SSU2, so the decision is immediate, on both families, with the
%% aggregate `{reachability, ssu2, firewalled}` event.
boot_firewalled_when_private_host_test() ->
    start_app(true),
    try
        ?assertEqual(firewalled, i2p_ssu2_reachability:status()),
        ?assertEqual(firewalled, i2p_ssu2_reachability:status(ipv4)),
        ?assertEqual(firewalled, i2p_ssu2_reachability:status(ipv6))
    after
        stop_app()
    end.

%% A non-private boot starts undecided and only resolves on the first
%% peer-test result: an `ok` marks the family reachable (and the aggregate
%% reachable), a later `firewalled` flips it back and re-emits the aggregate.
peertest_results_reachability_test() ->
    start_app(false),
    try
        ?assertEqual(unknown, i2p_ssu2_reachability:status()),
        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        try
            i2p_events:notify({peertest_result, ipv4, ok}),
            %% The decision is applied asynchronously: wait for the event the
            %% transition emits, then the state is committed.
            ?assertEqual({reachability, ssu2, reachable}, collect()),
            ?assertEqual(reachable, wait_status({status, ipv4}, reachable)),
            ?assertEqual(reachable, wait_status(status, reachable)),

            i2p_events:notify({peertest_result, ipv4, firewalled}),
            ?assertEqual({reachability, ssu2, firewalled}, collect()),
            ?assertEqual(firewalled, wait_status({status, ipv4}, firewalled)),
            ?assertEqual(firewalled, wait_status(status, firewalled)),

            %% Undecided results never move the family nor
            %% emit (the mailbox stays quiet after the firewalled event).
            i2p_events:notify({peertest_result, ipv6, unknown}),
            ?assertEqual(unknown, i2p_ssu2_reachability:status(ipv6)),
            ?assertEqual(firewalled, i2p_ssu2_reachability:status())
        after
            gen_event:delete_handler(i2p_events, i2p_events_tests_collector, [])
        end
    after
        stop_app()
    end.

%% ----------------------------------------------------------------------
%% Fixture

start_app(AllowPrivateHost) ->
    catch application:stop(i2per),
    ok = application:set_env(i2per, allow_private_host, AllowPrivateHost),
    {ok, _} = application:ensure_all_started(i2per),
    ?assert(is_pid(whereis(i2p_ssu2_reachability))),
    ok.

stop_app() ->
    _ = application:stop(i2per),
    _ = application:unset_env(i2per, allow_private_host),
    ok.

%% Poll `Query` (a `status/0` or `{status, Family}` call) until it equals
%% `Expected`, or fail after 2 s. The reachability decision is applied
%% asynchronously after the peertest event, so assertions on it must wait.
wait_status(Query, Expected) ->
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    wait_status(Query, Expected, Deadline).

wait_status(Query, Expected, Deadline) ->
    Current =
        case Query of
            status -> i2p_ssu2_reachability:status();
            {status, Family} -> i2p_ssu2_reachability:status(Family)
        end,
    case {Current, erlang:monotonic_time(millisecond) > Deadline} of
        {Expected, _} ->
            Expected;
        {_, true} ->
            erlang:error({status_timeout, Query, Expected, Current});
        _ ->
            timer:sleep(20),
            wait_status(Query, Expected, Deadline)
    end.

collect() ->
    receive
        {reachability, ssu2, _} = Event ->
            Event
    after 2000 ->
        erlang:error({reachability_event_timeout, self()})
    end.
