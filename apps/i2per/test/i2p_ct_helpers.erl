%% Shared Common Test support helpers for the i2per suites:
%%
%% - a per-test-case data directory, isolated under the CT priv dir;
%% - an ephemeral port reservation for suites that bind their own listeners;
%% - an event-driven wait/poll that never sleeps a fixed total — each test that
%%   needs a condition to become true polls with a backoff until a deadline,
%%   and a receive wrapper skips (drains) non-matching messages, so a leftover
%%   message from a previous case cannot poison a later assertion.
%%
%% Test code is not rendered by ExDoc (docs are generated from the `default`
%% profile ebin dirs), so this module carries only header comments.

-module(i2p_ct_helpers).

-export([
    temp_data_dir/1,
    free_port/0,
    await/1,
    await/2,
    wait_msg/2,
    start_ssu2_trace/0,
    stop_ssu2_trace/0,
    dump_ssu2_trace/0
]).

-define(SSU2_TRACE_MAX, 512).

%% A directory that exists and is writable for the current test case, created
%% beneath the CT priv dir. Store it in Config as `{temp_data_dir, Dir}` and
%% pass Config back in on every call so each case gets a fresh, isolated one.
-spec temp_data_dir(Config) -> string() when Config :: proplists:proplist().
temp_data_dir(Config) ->
    Dir = filename:join(private_dir(Config), "data"),
    ok = filelib:ensure_dir(filename:join(Dir, "_")),
    Dir.

private_dir(Config) ->
    case proplists:get_value(priv_dir, Config) of
        undefined ->
            Base = filename:join(ct:log_dir(), "priv_" ++ os:getpid()),
            ok = filelib:ensure_dir(filename:join(Base, "_")),
            Base;
        Priv ->
            Priv
    end.

%% Reserve an ephemeral TCP port. The port is released on return; the caller
%% must bind it immediately (typical for test listeners) — this is a race-free
%% convenience, not a lease.
-spec free_port() -> inet:port_number().
free_port() ->
    {ok, Sock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Sock),
    ok = gen_tcp:close(Sock),
    Port.

%% Poll `Fun` (a zero-arity predicate) until it returns true or the default
%% 10-second deadline passes, then fail with error(timeout). No fixed sleeps.
-spec await(fun(() -> boolean())) -> ok.
await(Fun) ->
    await(Fun, 10000).

-spec await(fun(() -> boolean()), non_neg_integer()) -> ok.
await(Fun, Timeout) when is_function(Fun, 0) ->
    await_loop(Fun, erlang:monotonic_time(millisecond) + Timeout).

await_loop(Fun, Deadline) ->
    case Fun() of
        true ->
            ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    await_timeout(Fun);
                false ->
                    timer:sleep(25),
                    await_loop(Fun, Deadline)
            end
    end.

%% Cold-path diagnostic for an await deadline miss, mirroring
%% `wait_msg_timeout/1`: classify the miss as predicate-late (the condition
%% became true just after the deadline -- a scheduling tail) versus missing
%% (it never became true, so the chain that should have set it stalled or
%% dropped), snapshot the mailbox, and dump the SSU2 trace when a collector is
%% registered. Without this an await timeout reports only `{timeout, ...}` and
%% cannot be told apart from a genuine production stall.
await_timeout(Fun) ->
    ct:pal(
        "await timeout; post-deadline predicate = ~0p~nmailbox = ~0p",
        [late_predicate(Fun), mailbox_summary(mailbox_snapshot(), 30)]
    ),
    case dump_ssu2_trace() of
        [] ->
            ok;
        Buffer ->
            ct:pal("ssu2 trace (~p events):~n~0p", [length(Buffer), Buffer])
    end,
    error(timeout).

%% Re-check the predicate once, after the deadline, so the log distinguishes a
%% late condition from a missing one. The try keeps a throwing predicate from
%% masking the original timeout with an unrelated crash; this is a diagnostic
%% path only and never changes the outcome, which is always error(timeout).
late_predicate(Fun) ->
    try Fun() of
        true -> predicate_late;
        false -> missing
    catch
        _Class:_Reason -> predicate_raised
    end.

mailbox_snapshot() ->
    case process_info(self(), messages) of
        {messages, Msgs} when is_list(Msgs) -> Msgs;
        _ -> []
    end.

%% Receive until a message matches `Pred` (a unary fun returning `{true, Value}`
%% or false). Non-matching messages are drained while the wait continues. Fails
%% with error(timeout) on the deadline.
-spec wait_msg(fun((term()) -> false | {true, term()}), non_neg_integer()) -> term().
wait_msg(Pred, Timeout) when is_function(Pred, 1) ->
    wait_msg_loop(Pred, erlang:monotonic_time(millisecond) + Timeout).

wait_msg_loop(Pred, Deadline) ->
    Now = erlang:monotonic_time(millisecond),
    case Now >= Deadline of
        true ->
            wait_msg_timeout(Pred);
        false ->
            receive
                Msg ->
                    case Pred(Msg) of
                        {true, Value} -> Value;
                        false -> wait_msg_loop(Pred, Deadline)
                    end
            after erlang:max(0, Deadline - Now) ->
                wait_msg_timeout(Pred)
            end
    end.

%% Cold-path diagnostic for a deadline miss: drain the mailbox once more and
%% classify whether the awaited value was present a hair late (mailbox-late is a
%% scheduling tail) or genuinely absent (the delivering process never forwarded
%% it because of a datagram loss or stalled chain). Log a compact snapshot in
%% either case. This follows the `observe_for_result/1` pattern in
%% `i2p_ssu2_peertest_SUITE`.
wait_msg_timeout(Pred) ->
    Mail = mailbox_snapshot(),
    Late = late_scan(Pred),
    ct:pal(
        "wait_msg timeout; post-deadline scan = ~0p~nmailbox (pre-drain) = ~0p",
        [Late, mailbox_summary(Mail, 30)]
    ),
    case dump_ssu2_trace() of
        [] ->
            ok;
        Buffer ->
            ct:pal("ssu2 trace (~p events):~n~0p", [length(Buffer), Buffer])
    end,
    error(timeout).

late_scan(Pred) ->
    receive
        Msg ->
            case Pred(Msg) of
                {true, Value} -> {mailbox_late, Value};
                false -> late_scan(Pred)
            end
    after 0 ->
        missing
    end.

mailbox_summary(undefined, _N) ->
    [];
mailbox_summary(Msgs, N) ->
    lists:sublist([summ_msg(M) || M <- Msgs], N).

summ_msg({ssu2_data, P, Blocks}) ->
    {ssu2_data, P, [summ_block(B) || B <- Blocks]};
summ_msg({ssu2_closed, P, Reason}) ->
    {ssu2_closed, P, Reason};
summ_msg({ssu2_ready, P, _Keys, RI}) ->
    {ssu2_ready, P, byte_size(RI)};
summ_msg({udp, S, _IP, _Port, Datagram}) ->
    {udp, S, byte_size(Datagram)};
summ_msg({ssu2_packet, Datagram}) ->
    {ssu2_packet, byte_size(Datagram)};
summ_msg({peertest_result, Result}) ->
    {peertest_result, Result};
summ_msg({'DOWN', _MRef, process, P, Info}) ->
    {down, P, Info};
summ_msg(M) when is_atom(M) ->
    M;
summ_msg(M) when is_tuple(M), tuple_size(M) > 0 ->
    {tuple, element(1, M), tuple_size(M)};
summ_msg(M) when is_tuple(M) ->
    {tuple, 0};
summ_msg(M) when is_binary(M) ->
    {binary, byte_size(M)};
summ_msg(_M) ->
    term.

summ_block({i2np, Type, MsgId, _ShortExp, Body}) ->
    {i2np, Type, MsgId, byte_size(Body)};
summ_block({first_fragment, Type, MsgId, _ShortExp, Body}) ->
    {first_fragment, Type, MsgId, byte_size(Body)};
summ_block({follow_on_fragment, FragNum, IsLast, MsgId, Body}) ->
    {follow_on_fragment, FragNum, IsLast, MsgId, byte_size(Body)};
summ_block({peertest, N, _Code, _Flags, _Hash, _Ver, _Nonce, _Ts, _Port, _Ip, _Sig}) ->
    {peertest, N};
summ_block({router_info, Flag, RIData}) ->
    {router_info, Flag, byte_size(RIData)};
summ_block({path_challenge, Data}) ->
    {path_challenge, byte_size(Data)};
summ_block({path_response, Data}) ->
    {path_response, byte_size(Data)};
summ_block(B) when is_tuple(B) ->
    {block, element(1, B), tuple_size(B)};
summ_block(B) ->
    {block, B}.

%% ------------------------------------------------------------------
%% SSU2 on-wire trace collector
%%
%% Register a collector under `i2p_ssu2_trace_sink`; the SSU2 session,
%% listener and PeerTest coordinator emit to it whenever it is registered.
%% The collector keeps the last ?SSU2_TRACE_MAX events and can hand them
%% back on demand. Used by the peertest suite's init_per_suite/end_per_suite
%% and dumped from wait_msg_timeout so a stalled test carries its own trace.

start_ssu2_trace() ->
    case whereis(i2p_ssu2_trace_sink) of
        Collector when is_pid(Collector) ->
            Collector;
        _NotRegistered ->
            Collector = spawn(fun() -> ssu2_trace_collector([]) end),
            true = register(i2p_ssu2_trace_sink, Collector),
            Collector
    end.

stop_ssu2_trace() ->
    Buffer = dump_ssu2_trace(),
    case Buffer of
        [] ->
            ok;
        _ ->
            ct:pal("ssu2 trace (final, ~p events):~n~0p", [length(Buffer), Buffer])
    end,
    i2p_ssu2_trace:disable().

dump_ssu2_trace() ->
    case i2p_ssu2_trace:sink() of
        Collector when is_pid(Collector) ->
            Collector ! {ssu2_trace_dump, self()},
            receive
                {ssu2_trace_dump_result, Buffer} -> Buffer
            after 1000 ->
                []
            end;
        _ ->
            []
    end.

ssu2_trace_collector(Events) ->
    receive
        {ssu2_trace, MonotonicMs, Pid, Label, Details} ->
            Event = {MonotonicMs, Pid, Label, Details},
            ssu2_trace_collector(lists:sublist([Event | Events], ?SSU2_TRACE_MAX));
        {ssu2_trace_dump, From} ->
            From ! {ssu2_trace_dump_result, lists:reverse(Events)},
            ssu2_trace_collector(Events);
        stop ->
            ok
    end.
