-module(i2p_events_forward_tests).

-moduledoc """
Tests for the `m:i2p_events_forward` remote-subscriber forwarder: every bus
event arrives as `{event, Event}` at the collector pid, and the remaining
gen_event callbacks behave sanely.
""".

-include_lib("eunit/include/eunit.hrl").

forwarding_test() ->
    %% Standalone gen_event manager with the forwarder as its only handler.
    {ok, Mgr} = gen_event:start_link(),
    try
        ok = gen_event:add_handler(Mgr, i2p_events_forward, [self()]),
        ok = gen_event:notify(Mgr, {sample, 42}),
        receive
            {event, {sample, 42}} -> ok
        after 5000 -> erlang:error(event_not_forwarded)
        end,
        %% handle_call on the handler: the unsupported-query shape returns ok
        %% (OTP 28 gen_event:call takes the handler module as second arg).
        ?assertEqual(ok, gen_event:call(Mgr, i2p_events_forward, query)),
        %% handle_info: a stray message to the manager must not crash it.
        %% Prove survival event-driven (no fixed sleep): notify again after
        %% the stray message and await that event.
        Mgr ! stray_message,
        ok = gen_event:notify(Mgr, {sample, 43}),
        receive
            {event, {sample, 43}} -> ok
        after 5000 -> erlang:error(manager_died_after_stray_message)
        end,
        ?assert(is_process_alive(Mgr))
    after
        ok = gen_event:stop(Mgr)
    end.

callbacks_test() ->
    %% init + code_change exercised directly (init also runs via add_handler
    %% above); both keep the collector pid as State.
    ?assertEqual({ok, self()}, i2p_events_forward:init([self()])),
    ?assertEqual({ok, self()}, i2p_events_forward:code_change(0, self(), [])),
    ?assertEqual(ok, i2p_events_forward:terminate(any, self())).
