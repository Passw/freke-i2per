-module(i2p_sam_forward_tests).

-moduledoc """
Direct unit tests for `m:i2p_sam_forward`, the FORWARD-session relay
machinery. The module is a plain helper (no process of its own), so every
`f:info/2` and `f:add_relay/3` branch is driven with crafted session-state
maps over real loopback sockets; the session's `i2p_stream_conn` casts land
in the test process's mailbox.
""".

-include_lib("eunit/include/eunit.hrl").

tcp_forward_test() ->
    {State, Accepted, Client, Listen} = relay_state(),
    {noreply, State2} = i2p_sam_forward:info({tcp, Accepted, <<"data">>}, State),
    ?assertEqual(State, State2),
    %% The payload reached the peer stream (a cast into our mailbox) and the
    %% socket was re-armed for one active receive.
    ?assert(lists:member({'$gen_cast', {send, <<"data">>}}, drain_mailbox())),
    ?assertEqual({ok, [{active, once}]}, inet:getopts(Accepted, [active])),
    %% A socket that is not a relay is unhandled.
    ?assertEqual(unhandled, i2p_sam_forward:info({tcp, Client, <<"x">>}, State)),
    teardown(Listen, Accepted, Client).

tcp_closed_test() ->
    {State, Accepted, Client, Listen} = relay_state(),
    {noreply, State2} = i2p_sam_forward:info({tcp_closed, Accepted}, State),
    ?assertEqual(#{}, maps:get(fwd_relays, State2)),
    ?assert(lists:member({'$gen_cast', close}, drain_mailbox())),
    ?assertEqual(unhandled, i2p_sam_forward:info({tcp_closed, Client}, State)),
    ?assertEqual(unhandled, i2p_sam_forward:info({tcp_closed, Accepted}, State2)),
    teardown(Listen, Accepted, Client).

tcp_error_test() ->
    {State, Accepted, Client, Listen} = relay_state(),
    {noreply, State2} = i2p_sam_forward:info({tcp_error, Accepted, econnreset}, State),
    ?assertEqual(#{}, maps:get(fwd_relays, State2)),
    ?assert(lists:member({'$gen_cast', close}, drain_mailbox())),
    teardown(Listen, Accepted, Client).

stream_established_dial_ok_test() ->
    State = #{fwd_relays => #{self() => #{mon => make_ref(), sock => undefined}}},
    {ok, Listen} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, Port} = inet:port(Listen),
    Dial = i2p_sam_forward:info(
        {stream_established, self(), <<"peerhash">>},
        State#{forward => #{host => {127, 0, 0, 1}, port => Port}}
    ),
    {noreply, DialedState} = Dial,
    ?assertNotEqual(undefined, maps:get(sock, maps:get(self(), maps:get(fwd_relays, DialedState)))),
    ?assertEqual(
        unhandled,
        i2p_sam_forward:info({stream_established, not_a_relay(), <<"p">>}, State)
    ),
    gen_tcp:close(Listen).

stream_established_dial_refused_test() ->
    State = #{fwd_relays => #{self() => #{mon => make_ref(), sock => undefined}}},
    {ok, L} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, RefusedPort} = inet:port(L),
    ok = gen_tcp:close(L),
    %% The bound-then-released port refuses the dial: the peer gets a graceful
    %% CLOSE and the relay is dropped, no local socket.
    Download = i2p_sam_forward:info(
        {stream_established, self(), <<"peerhash">>},
        State#{forward => #{host => {127, 0, 0, 1}, port => RefusedPort}}
    ),
    ?assertMatch({noreply, #{fwd_relays := #{}}}, Download),
    {noreply, DialedState} = Download,
    ?assertEqual(#{}, maps:get(fwd_relays, DialedState)),
    ?assert(lists:member({'$gen_cast', close}, drain_mailbox())).

stream_started_test() ->
    Owner = ensure_sam_sup_table(),
    State0 = #{
        fwd_relays => #{self() => #{mon => make_ref(), sock => undefined}},
        dest_hash => <<"desthash">>
    },
    State = i2p_sam_forward:add_relay(not_a_relay(), make_ref(), State0),
    try
        ?assertEqual(
            {noreply, State0},
            i2p_sam_forward:info({stream_started, self(), 7}, State0)
        ),
        ?assertEqual(
            [{{conn, <<"desthash">>, 7}, self()}],
            ets:lookup(i2p_sam_sup, {conn, <<"desthash">>, 7})
        ),
        ?assertEqual(unhandled, i2p_sam_forward:info({stream_started, not_a_relay(), 8}, State))
    after
        catch ets:delete(i2p_sam_sup, {conn, <<"desthash">>, 7}),
        %% Only tear down the table we ourselves created: a booted router's
        %% SAM supervisor owns a live one, and deleting it would break the app.
        case Owner of
            created -> catch ets:delete(i2p_sam_sup);
            existing -> ok
        end
    end.

stream_data_test() ->
    {State, Accepted, Client, Listen} = relay_state(),
    {noreply, State2} = i2p_sam_forward:info({stream_data, self(), <<"bytes">>}, State),
    ?assertEqual({ok, <<"bytes">>}, gen_tcp:recv(Client, 0, 2000)),
    ?assertEqual(unhandled, i2p_sam_forward:info({stream_data, not_a_relay(), <<"b">>}, State2)),
    teardown(Listen, Accepted, Client).

stream_close_reset_down_test() ->
    State = #{fwd_relays => #{self() => #{mon => make_ref(), sock => undefined}}},
    Other = not_a_relay(),
    ?assertEqual(unhandled, i2p_sam_forward:info({stream_closed, Other}, State)),
    ?assertEqual(unhandled, i2p_sam_forward:info({stream_reset, Other}, State)),
    ?assertEqual(
        unhandled,
        i2p_sam_forward:info({'DOWN', make_ref(), process, Other, normal}, State)
    ),
    info_down(State).

info_down(State) ->
    {noreply, DownState} = i2p_sam_forward:info({stream_closed, self()}, State),
    ?assertEqual(#{}, maps:get(fwd_relays, DownState)).

add_relay_test() ->
    State = i2p_sam_forward:add_relay(self(), make_ref(), #{}),
    Relays = maps:get(fwd_relays, State),
    ?assert(maps:is_key(self(), Relays)),
    #{mon := _, sock := undefined} = maps:get(self(), Relays).

unhandled_test() ->
    State = #{fwd_relays => #{}},
    ?assertEqual(unhandled, i2p_sam_forward:info({totally, unrelated}, State)).

%% A process that can never be (and is never) in a relay map.
not_a_relay() ->
    P = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    unlink(P),
    P.

%% The demux table is normally booted by the SAM supervisor; make sure it is
%% present so the `stream_started` registration can insert into it.
ensure_sam_sup_table() ->
    case ets:whereis(i2p_sam_sup) of
        undefined ->
            ets:new(i2p_sam_sup, [set, public, named_table]),
            created;
        _ ->
            existing
    end.

%% A relay whose local service socket is a freshly accepted loopback socket, so
%% inet:setopts/gen_tcp:send/close all work; the peer-stream cast targets the
%% test process's mailbox. The relay's Conn is the test process itself.
relay_state() ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, Port} = inet:port(Listen),
    {ok, Client} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    {ok, Accepted} = gen_tcp:accept(Listen, 2000),
    Relays = #{self() => #{mon => make_ref(), sock => Accepted}},
    State = #{fwd_relays => Relays, forward => #{host => {127, 0, 0, 1}, port => Port}},
    {State, Accepted, Client, Listen}.

teardown(Listen, Accepted, Client) ->
    gen_tcp:close(Accepted),
    gen_tcp:close(Client),
    gen_tcp:close(Listen).

drain_mailbox() ->
    drain_mailbox([]).
drain_mailbox(Acc) ->
    receive
        M -> drain_mailbox([M | Acc])
    after 0 -> Acc
    end.
