-module(i2p_lookup_srv_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_lookup_srv`.

Covers the gen_server surface and the pure failure paths (missing pending key,
stale timers, dropped callers, catch-alls), plus the full "no candidates, give
up" orchestration against a live-but-empty `m:i2p_netdb_srv` (no floodfills,
no rows): a `find` arms the pipeline, the single attempt round finds no target
and `fail/2` answers the caller `{error, not_found}`. The tunnel-carrying
DatabaseLookup chase (`f:i2p_lookup_srv:send_lookup/4`) needs live tunnels and
is covered by `m:i2p_lookup_srv_SUITE`.
""".

-include_lib("eunit/include/eunit.hrl").

-define(HASH, <<16#A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5:256>>).

init_test() ->
    {ok, State} = i2p_lookup_srv:init([?HASH]),
    ?assertEqual(#{pending => #{}, our_hash => ?HASH}, State).

%% stop/0 on a running orchestrator (and idempotently on a stopped one).
stop_test() ->
    Stop = fun() ->
        case whereis(i2p_lookup_srv) of
            undefined ->
                {ok, _} = i2p_lookup_srv:start_link(?HASH),
                ?assertEqual(ok, i2p_lookup_srv:stop());
            _ ->
                ?assertEqual(ok, i2p_lookup_srv:stop())
        end
    end,
    Stop(),
    ?assertEqual(undefined, whereis(i2p_lookup_srv)),
    Stop(),
    ?assertEqual(undefined, whereis(i2p_lookup_srv)).

not_running_test() ->
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ls(?HASH)),
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ri(?HASH)).

%% A RouterInfo already in the NetDb resolves immediately from cache.
cached_ri_hit_test() ->
    Owner = ensure_netdb(),
    try
        RI = mk_ri(),
        Hash = i2p_router_info:hash(RI),
        added = i2p_netdb_srv:store(RI, erlang:system_time(millisecond)),
        {ok, State} = i2p_lookup_srv:init([?HASH]),
        {reply, {ok, ReplyRI}, State} =
            i2p_lookup_srv:handle_call({find, Hash, router}, {self(), make_ref()}, State),
        ?assertEqual(Hash, i2p_router_info:hash(ReplyRI))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A DatabaseStore landing for a pending key that still misses the NetDb:
%% answered {error, not_found} and dropped.
resolve_stored_miss_test() ->
    Owner = ensure_netdb(),
    try
        Key = <<1:256>>,
        {ok, State0} = i2p_lookup_srv:init([?HASH]),
        %#callers empty
        P = pending(),
        Me = self(),
        Ref = make_ref(),
        From = {Me, Ref},
        Entry = P#{callers := [{From, Me, make_ref()}]},
        {noreply, State1} = i2p_lookup_srv:handle_info(
            {db_stored, Key, router}, State0#{pending := #{Key => Entry}}
        ),
        ?assertEqual(#{}, maps:get(pending, State1)),
        receive
            {Ref, {error, not_found}} -> ok
        after 0 ->
            error(no_reply)
        end
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% Two waiters on the same key share one pending entry (the duplicate-waiter
%% branch); with no floodfill candidates both fail together.
two_callers_shared_pending_test() ->
    Owner = ensure_netdb(),
    try
        Key = <<2:256>>,
        {ok, State} = i2p_lookup_srv:init([?HASH]),
        Me = self(),
        R1 = make_ref(),
        R2 = make_ref(),
        {noreply, State1} =
            i2p_lookup_srv:handle_call({find, Key, lease}, {Me, R1}, State),
        {noreply, State2} =
            i2p_lookup_srv:handle_call({find, Key, lease}, {Me, R2}, State1),
        #{Key := Entry} = maps:get(pending, State2),
        ?assertEqual(2, length(maps:get(callers, Entry))),
        {noreply, State3} = i2p_lookup_srv:handle_info({next_attempt, Key}, State2),
        ?assertEqual(#{}, maps:get(pending, State3)),
        receive
            {R1, {error, not_found}} -> ok
        after 0 ->
            error(no_reply)
        end,
        receive
            {R2, {error, not_found}} -> ok
        after 0 ->
            error(no_reply)
        end
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% An entry at the attempt budget caps out: fail-fast without any candidate.
exhausted_attempts_test() ->
    Key = <<3:256>>,
    {ok, State0} = i2p_lookup_srv:init([?HASH]),
    Entry = (pending())#{attempts := 5},
    {noreply, State1} = i2p_lookup_srv:handle_info(
        {next_attempt, Key}, State0#{pending := #{Key => Entry}}
    ),
    ?assertEqual(#{}, maps:get(pending, State1)).

%% A dying caller is dropped from its pending entry; the entry lives while any
%% caller remains and dies with its last one.
drop_caller_test() ->
    Key = <<4:256>>,
    {ok, State0} = i2p_lookup_srv:init([?HASH]),
    Me = self(),
    DeadPid = spawn(fun() -> ok end),
    Ref = make_ref(),
    %% First waiter dies, second lives: entry survives with the live caller.
    S1 = State0#{
        pending := #{
            Key => (pending())#{
                callers := [
                    {{Me, make_ref()}, DeadPid, Ref},
                    {{Me, make_ref()}, Me, make_ref()}
                ]
            }
        }
    },
    {noreply, S2} = i2p_lookup_srv:handle_info({'DOWN', Ref, process, DeadPid, normal}, S1),
    #{Key := K1} = maps:get(pending, S2),
    ?assertEqual(1, length(maps:get(callers, K1))),
    %% The last waiter dies: the whole entry goes with it.
    RefLast = make_ref(),
    S3 = State0#{
        pending := #{
            Key => K1#{
                callers := [
                    {{Me, make_ref()}, Me, RefLast}
                ]
            }
        }
    },
    {noreply, S4} = i2p_lookup_srv:handle_info({'DOWN', RefLast, process, Me, normal}, S3),
    ?assertEqual(#{}, maps:get(pending, S4)).

generic_call_test() ->
    ?assertEqual(
        {reply, ok, base_state()},
        i2p_lookup_srv:handle_call(junk, from(), base_state())
    ).

generic_cast_test() ->
    ?assertEqual({noreply, base_state()}, i2p_lookup_srv:handle_cast(junk, base_state())).

generic_info_test() ->
    ?assertEqual({noreply, base_state()}, i2p_lookup_srv:handle_info(junk, base_state())).

%% Missing-key handler paths: every clause degrades to the unchanged state.
missing_key_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_lookup_srv:handle_info({next_attempt, <<"x">>}, State)),
    ?assertEqual({noreply, State}, i2p_lookup_srv:handle_info({db_stored, <<"x">>, lease}, State)),
    ?assertEqual({noreply, State}, i2p_lookup_srv:handle_info({search_reply, <<"x">>, []}, State)),
    ?assertEqual(
        {noreply, State},
        i2p_lookup_srv:handle_info({attempt_timeout, <<"x">>, make_ref()}, State)
    ),
    ?assertEqual(
        {noreply, State},
        i2p_lookup_srv:handle_info({'DOWN', make_ref(), process, self(), normal}, State)
    ).

%% Orchestration with a live, empty NetDb: one caller, zero floodfill
%% candidates, so the single attempt round fails with {error, not_found}.
orchestration_give_up_test() ->
    Owner = ensure_netdb(),
    try
        Key = <<1:256>>,
        Ref = make_ref(),
        {ok, InitState} = i2p_lookup_srv:init([?HASH]),
        {noreply, State1} =
            i2p_lookup_srv:handle_call({find, Key, lease}, {self(), Ref}, InitState),
        Me = self(),
        ?assertMatch(
            #{Key := #{kind := lease, attempts := 0, callers := [{_, Me, _}]}},
            maps:get(pending, State1)
        ),
        {noreply, State2} = i2p_lookup_srv:handle_info({next_attempt, Key}, State1),
        ?assertEqual(#{}, maps:get(pending, State2)),
        receive
            {Ref, {error, not_found}} ->
                ok
        after 0 ->
            error(no_reply)
        end,
        %% Same give-up when the current attempt timer fires (timer-ref branch).
        Ref2 = make_ref(),
        Entry = #{
            kind => router,
            callers => [],
            tried => [],
            chase => [],
            attempts => 0,
            deadline => erlang:monotonic_time(millisecond) + 1000,
            timer => Ref2
        },
        State3 = base_state(),
        {noreply, State4} = i2p_lookup_srv:handle_info(
            {attempt_timeout, Key, Ref2}, State3#{pending := #{Key => Entry}}
        ),
        ?assertEqual(#{}, maps:get(pending, State4))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% %% %%% Internal %%% %%

base_state() ->
    #{pending => #{}, our_hash => ?HASH}.

from() ->
    {self(), make_ref()}.

%% A well-formed pending entry: no callers, nothing tried, lifetime fresh.
pending() ->
    #{
        kind => router,
        callers => [],
        tried => [],
        chase => [],
        attempts => 0,
        deadline => erlang:monotonic_time(millisecond) + 60_000,
        timer => undefined
    }.

mk_ri() ->
    #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
    i2p_router_info:build(Id, erlang:system_time(millisecond), [], #{}, SignSeed).

ensure_netdb() ->
    application:unset_env(i2per, data_dir),
    case whereis(i2p_netdb_srv) of
        undefined ->
            {ok, _Pid} = i2p_netdb_srv:start_link(),
            started;
        _Pid ->
            existing
    end.
