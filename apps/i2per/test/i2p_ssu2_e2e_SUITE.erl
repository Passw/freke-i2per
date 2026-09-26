%% SSU2 end-to-end session and data-path tests. Each case owns its process,
%% mailbox, application lifecycle, and network fixtures. Every wait drains
%% non-matching messages through `i2p_ct_helpers`.
%%
%% The suite covers session establishment, bidirectional I2NP delivery,
%% keepalive and idle handling, fragmentation, and malformed-datagram
%% tolerance. Deterministic handshake-recovery cases live in
%% `i2p_ssu2_handshake_SUITE`; they inject delayed and lost SessionCreated
%% replies and verify the public connection result without a test-level retry.

-module(i2p_ssu2_e2e_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    full_handshake_and_data/1,
    keepalive_roundtrip/1,
    idle_reaps_silent_session/1,
    large_fragmented_message_reassembled/1,
    garbage_datagram_survives/1
]).

-define(APP, i2per).
-define(DATA_WINDOW, 15000).
-define(RELAY_WINDOW, 20000).

suite() ->
    [].

all() ->
    [
        full_handshake_and_data,
        keepalive_roundtrip,
        idle_reaps_silent_session,
        large_fragmented_message_reassembled,
        garbage_datagram_survives
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: env must be set before the app (and its SSU2 sup) come
%% up; app stop tears down the SSU2 session/listener tree (all `temporary`
%% children of i2p_ssu2_sup), so nothing leaks into the next testcase.
%% ---------------------------------------------------------------------------

init_per_testcase(full_handshake_and_data, Config) ->
    start_app(Config, 60000);
init_per_testcase(keepalive_roundtrip, Config) ->
    ok = application:set_env(?APP, keepalive_interval_ms, 300),
    ok = application:set_env(?APP, idle_timeout_ms, 60000),
    start_app(Config, 120000);
init_per_testcase(idle_reaps_silent_session, Config) ->
    ok = application:set_env(?APP, idle_timeout_ms, 1000),
    ok = application:set_env(?APP, keepalive_interval_ms, 60000),
    start_app(Config, 30000);
init_per_testcase(large_fragmented_message_reassembled, Config) ->
    start_app(Config, 60000);
init_per_testcase(garbage_datagram_survives, Config) ->
    start_app(Config, 30000).

start_app(Config, Timetrap) ->
    i2p_ct_helpers:start_ssu2_trace(),
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, Timetrap} | Config].

end_per_testcase(keepalive_roundtrip, _Config) ->
    teardown();
end_per_testcase(idle_reaps_silent_session, _Config) ->
    teardown();
end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

teardown() ->
    ok = application:unset_env(?APP, keepalive_interval_ms),
    ok = application:unset_env(?APP, idle_timeout_ms),
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

%% ---------------------------------------------------------------------------
%% Session + data path
%% ---------------------------------------------------------------------------

%% Full loopback handshake (Retry token grant, SessionConfirmed RouterInfo
%% validation, Bob's ACK of packet zero) then data both directions and a clean
%% termination observed at the peer.
full_handshake_and_data(_Config) ->
    {APid, BPid} = establish_pair(),
    MsgBody = <<"hello over ssu2">>,
    i2p_ssu2_conn:send_i2np(APid, 6, 4242, MsgBody),
    ok = wait_i2np(BPid, 4242, MsgBody),
    Reply = <<"reply from bob">>,
    i2p_ssu2_conn:send_i2np(BPid, 6, 4243, Reply),
    ok = wait_i2np(APid, 4243, Reply),
    i2p_ssu2_conn:terminate_session(APid, 0),
    ok = wait_closed(BPid, 0).

%% Data-phase keepalive: with a short keepalive interval the session sends a
%% path_challenge (type 18) probe and the peer echoes it as a path_response
%% (type 19). Two full exchanges prove the cadence keeps firing; the echoed
%% data must match the challenge byte-for-byte.
%%
%% The capture is one pass over both sessions' block streams so a block is
%% never dropped by a competing wait. The response echo is cross-checked by
%% set membership against the challenges actually captured: both ends probe on
%% the same 300ms cadence and loopback echo is effectively in-order, but a
%% challenge captured seconds after its echo already hit the peer's mailbox
%% can make pairwise sequence ordering unreliable. The single receive loop keeps
%% both directions observable.
keepalive_roundtrip(_Config) ->
    {APid, BPid} = establish_pair(),
    {Cs, Rs} = capture_exchanges(BPid, APid, 2),
    true = lists:all(fun(D) -> byte_size(D) =:= 8 end, Cs),
    true = lists:all(fun(R) -> lists:member(R, Cs) end, Rs),
    true = is_process_alive(APid),
    true = is_process_alive(BPid).

%% Consume `N` path_challenges seen by `ChPid` and `N` path_responses seen by
%% `ResPid` in one receive loop, so no block is lost to a sibling wait and no
%% message is consumed twice. Blocks of the other tag on either session are
%% ignored, not drained-and-lost.
capture_exchanges(ChPid, ResPid, N) ->
    capture_exchanges(ChPid, ResPid, N, [], []).

capture_exchanges(_ChPid, _ResPid, N, Cs, Rs) when length(Cs) >= N, length(Rs) >= N ->
    {lists:reverse(Cs), lists:reverse(Rs)};
capture_exchanges(ChPid, ResPid, N, Cs, Rs) ->
    receive
        {ssu2_data, ChPid, Blocks} ->
            NewCs = append_blocks(Cs, path_challenge, Blocks, N),
            capture_exchanges(ChPid, ResPid, N, NewCs, Rs);
        {ssu2_data, ResPid, Blocks} ->
            NewRs = append_blocks(Rs, path_response, Blocks, N),
            capture_exchanges(ChPid, ResPid, N, Cs, NewRs)
    after ?RELAY_WINDOW ->
        erlang:error({keepalive_exchange_incomplete, length(Cs), length(Rs)})
    end.

append_blocks(Acc, Tag, Blocks, N) when length(Acc) < N ->
    Taken = [D || {T, D} <- Blocks, T =:= Tag],
    lists:sublist(Acc ++ Taken, N);
append_blocks(Acc, _Tag, _Blocks, _N) ->
    Acc.

%% Idle reap: with a short idle timeout and keepalive far away, a quiet
%% established session reaps itself — both ends exit `{idle_timeout,
%% no_activity}`.
idle_reaps_silent_session(_Config) ->
    {APid, BPid} = establish_pair(),
    expect_idle_exit([APid, BPid]).

%% A large I2NP message exceeds the per-packet budget and is fragmented across
%% several Data packets; the peer reassembles the exact body.
large_fragmented_message_reassembled(_Config) ->
    {APid, BPid} = establish_pair(),
    BigBody = crypto:strong_rand_bytes(6000),
    MsgId = 9000,
    i2p_ssu2_conn:send_i2np(APid, 6, MsgId, BigBody),
    ok = wait_i2np(BPid, MsgId, BigBody).

%% A random (non-session) datagram reaching the listener must never kill it:
%% the listener survives garbage and still answers.
garbage_datagram_survives(_Config) ->
    {_BPub, BPriv} = i2p_crypto:x25519_keygen(),
    Local =
        #{
            static_priv => BPriv,
            static_pub => crypto:strong_rand_bytes(32),
            intro_key => crypto:strong_rand_bytes(32)
        },
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, Local, self()),
    Port = i2p_ssu2_listener:port(Listener),
    {ok, Sock} = gen_udp:open(0, [binary]),
    ok =
        gen_udp:send(
            Sock,
            {127, 0, 0, 1},
            Port,
            crypto:strong_rand_bytes(120)
        ),
    ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, <<1, 2, 3>>),
    Port = i2p_ssu2_listener:port(Listener),
    gen_udp:close(Sock),
    ok.

%% ---------------------------------------------------------------------------
%% Helpers for the session pair and wire assertions.
%% ---------------------------------------------------------------------------

%% Stand up an Alice and a Bob session over two loopback listeners, with both
%% owners confirmed and the derived direction keys checked to agree.
establish_pair() ->
    {BPub, BPriv} = i2p_crypto:x25519_keygen(),
    Bik = crypto:strong_rand_bytes(32),
    BobLocal = #{static_priv => BPriv, static_pub => BPub, intro_key => Bik},
    {ok, BobListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    BobPort = i2p_ssu2_listener:port(BobListener),
    {ALocal, RIBlock} = alice_local(),
    {ok, AliceListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, ALocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => BobPort,
            static_key => BPub,
            intro_key => Bik
        },
    {ok, APid, KeysA} = i2p_ssu2_conn:connect(ALocal, RemoteOpts, RIBlock, AliceListener),
    #{k_ab := KAbA, k_ba := KBaA} = KeysA,
    BPid =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_ready, P, KeysB, _RemoteRI}) ->
                    #{k_ab := KAbB, k_ba := KBaB} = KeysB,
                    KAbA = KAbB,
                    KBaA = KBaB,
                    {true, P};
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ),
    unlink(APid),
    unlink(BPid),
    {APid, BPid}.

%% Wait until `FromPid`'s session delivers the I2NP message `MsgId`/`Body`.
%% Non-matching session messages are drained; a premature close of the awaited
%% session fails the wait (closed_early).
wait_i2np(FromPid, MsgId, Body) ->
    Result =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_data, P, Blocks}) when P =:= FromPid ->
                    case lists:keyfind(i2np, 1, Blocks) of
                        {i2np, _, MsgId, _, Body} -> {true, ok};
                        _ -> false
                    end;
                ({ssu2_closed, P, _Reason}) when P =:= FromPid ->
                    erlang:error(closed_early);
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ),
    ok = Result.

%% Wait for the peer session to announce a clean termination with `Reason`.
wait_closed(Pid, Reason) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_closed, P, R}) when P =:= Pid, R =:= Reason -> {true, ok};
            (_) -> false
        end,
        ?DATA_WINDOW
    ).

%% Assert every pid exits with `{idle_timeout, no_activity}` within the window.
%% All monitors are armed before any is awaited so the two sessions' exits
%% (which may be microseconds apart) cannot be missed as a `noproc` DOWN.
expect_idle_exit(Pids) ->
    Refs = [{erlang:monitor(process, Pid), Pid} || Pid <- Pids],
    lists:foreach(
        fun({MRef, Pid}) ->
            receive
                {'DOWN', MRef, process, Pid, {idle_timeout, no_activity}} ->
                    ok;
                {'DOWN', MRef, process, Pid, Other} ->
                    erlang:error({unexpected_exit, Pid, Other})
            after 5000 ->
                erlang:error({not_idle_reaped, Pid})
            end
        end,
        Refs
    ).

alice_local() ->
    {APub, APriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(APub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19150, APub, IntroKey),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI =
        i2p_router_info:build(
            Identity,
            erlang:system_time(millisecond),
            [Addr],
            Opts,
            Seed
        ),
    ALocal = #{static_priv => APriv, static_pub => APub, intro_key => IntroKey},
    {ALocal#{sign_seed => Seed, sign_pub => SignPub}, maps:get(binary, RI)}.
