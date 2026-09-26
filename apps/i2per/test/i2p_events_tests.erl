-module(i2p_events_tests).

-moduledoc """
Tests for the `m:i2p_events` bus: manager lifecycle under the real router
application and end-to-end delivery into a subscriber handler.

The emit sites themselves (tunnel builds, LeaseSet publication, SAM session
lifecycle) are exercised implicitly by every tunnel/SAM e2e suite — a bad
notification there would crash those processes and fail those suites.
""".

-include_lib("eunit/include/eunit.hrl").

%% Collecting gen_event handler: forwards every event to the test process.
collector_test() ->
    %% The assertion below matches the exact event this test sends. Other
    %% eunit tests must not leave stray messages in the shared worker's
    %% mailbox, or this partition would see them first.
    {ok, _} = application:ensure_all_started(i2per),
    ?assert(is_pid(whereis(i2p_events))),
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    try
        Hash = crypto:strong_rand_bytes(32),
        ok = i2p_events:notify({leaseset_published, Hash}),
        ?assertEqual({leaseset_published, Hash}, collect())
    after
        gen_event:delete_handler(i2p_events, i2p_events_tests_collector, [])
    end.

notify_without_manager_test() ->
    %% Best-effort contract: notify/1 returns ok even when the manager is
    %% absent. Genuine absence requires stopping the app (the manager is the
    %% first sup child and normally up), so stop it, hit the fallthrough, then
    %% restore so the rest of the run sees the router up again.
    _ = application:stop(i2per),
    try
        ?assertEqual(undefined, whereis(i2p_events)),
        ?assertEqual(ok, i2p_events:notify({config_changed, transit_max_tunnels, 5}))
    after
        catch application:ensure_all_started(i2per)
    end.

manager_callbacks_test() ->
    %% The manager ships with no built-in handlers, so its own gen_event
    %% callbacks are never reached through the live bus (events fan out to
    %% subscriber handlers). The callbacks are still part of the behaviour
    %% surface and exported; exercise them directly.
    ?assertEqual({ok, []}, i2p_events:init([])),
    ?assertEqual({ok, []}, i2p_events:handle_event(some_event, [])),
    ?assertEqual({ok, {error, unsupported}, []}, i2p_events:handle_call(query, [])),
    ?assertEqual({ok, []}, i2p_events:handle_info(irrelevant, [])),
    ?assertEqual(ok, i2p_events:terminate(any, [])),
    ?assertEqual({ok, []}, i2p_events:code_change(0, [], [])).

collect() ->
    %% The event fans out over the i2p_events gen_event bus asynchronously; a
    %% fixed window races the scheduler. Drain non-matching messages (incl.
    %% boot-time normal exits) and wait on a deadline instead.
    i2p_ct_helpers:wait_msg(
        fun(Ev) ->
            case Ev of
                {'EXIT', _, _} -> false;
                Event -> {true, Event}
            end
        end,
        5000
    ).
