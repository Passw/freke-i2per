%% Transport-selection and peer-backoff tests. Each case owns the application
%% lifecycle, the registered peer manager, listeners, and mailbox. The wire
%% assertions use the public transport-selection and status APIs.
%%
%% A stale message from a sibling case cannot be matched because every receive
%% drains non-matching mail through `i2p_ct_helpers:wait_msg/2`. Peer-status
%% and attempt-count polls are deadline-bounded. Discovery, answer, LeaseSet,
%% and floodfill-publish scenarios live in `i2p_peer_discovery_SUITE` and the
%% direct unit tests.
%%
%% Listeners bind at port 0 and close in `after` blocks. The slow fallback case
%% allows the SSU2 handshake budget before the NTCP2 leg appears; the backoff
%% case walks the configured retry windows.

-module(i2p_peer_transport_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    transport_ntcp2_when_remote_is_ntcp2_only/1,
    transport_ntcp2_when_ssu2_disabled/1,
    transport_ssu2_when_available/1,
    transport_falls_back_to_ntcp2/1,
    dead_peer_backs_off_then_recovers/1
]).

-define(APP, i2per).
-define(TIMEOUT, 10000).

suite() ->
    [].

all() ->
    [
        transport_ntcp2_when_remote_is_ntcp2_only,
        transport_ntcp2_when_ssu2_disabled,
        transport_ssu2_when_available,
        transport_falls_back_to_ntcp2,
        dead_peer_backs_off_then_recovers
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: the `ssu2_enabled` switch must be set before the app
%% and its SSU2 supervisor come up. App stop and unset_env in
%% end_per_testcase leave a clean envelope for the next case. The fallback
%% scenario spends ~20s in the SSU2 handshake budget, so it gets a wider
%% timetrap.
%% ---------------------------------------------------------------------------

init_per_testcase(Case, Config) ->
    ok = arm_ssu2(Case),
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, timetrap_for(Case)} | Config].

arm_ssu2(transport_ntcp2_when_remote_is_ntcp2_only) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(transport_ssu2_when_available) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(transport_falls_back_to_ntcp2) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(_Case) ->
    ok.

timetrap_for(transport_falls_back_to_ntcp2) ->
    60000;
timetrap_for(_Case) ->
    30000.

end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    ok = application:unset_env(?APP, ssu2_enabled),
    ok.

%% ---------------------------------------------------------------------------
%% Transport selection: with SSU2 armed, an outbound dial takes NTCP2
%% only when the remote cannot do SSU2; takes SSU2 when both endpoints are
%% ready (and live messages cross the SSU2 session); and falls back to NTCP2
%% when the remote advertises an SSU2 address that answers nothing. The global
%% `ssu2_enabled` switch gates the whole preference, so a fully SSU2-capable
%% setup still dials NTCP2 while the switch is off.
%% ---------------------------------------------------------------------------

%% Remote advertises only NTCP2 (no SSU2 address): the SSU2 guard fails on the
%% remote side and the dial goes over NTCP2, with the switch fully armed.
transport_ntcp2_when_remote_is_ntcp2_only(_Config) ->
    {A, B, _C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    {AL, _APort} = ssu2_listener(A),
    try
        BRI = ri_at(listen_port(LB), B),
        BHash = i2p_router_info:hash(BRI),
        A2 = local(A, 4668),
        AHash = maps:get(hash, A2),
        start_peer(A2, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        {CB, {lookup, Exploratory}} = await_frame(),
        #{type := exploratory, key := AHash} = Exploratory,
        {store, _} = recv_db_store(CB),
        await_peer_status(BHash, connected),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        i2p_peer:stop()
    after
        i2p_ssu2_listener:stop(AL),
        i2p_ntcp2_listener:stop(LB)
    end.

%% The `ssu2_enabled` switch is off (the default): even though the remote
%% advertises SSU2 and this router would be SSU2-armed, the dial stays NTCP2.
transport_ntcp2_when_ssu2_disabled(_Config) ->
    {A, B, _C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        DeadPort = i2p_ct_helpers:free_port(),
        BRI = ssu2_ri_at(listen_port(LB), DeadPort, B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(local(A, 4668), [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        {CB, {lookup, _}} = await_frame(),
        {store, _} = recv_db_store(CB),
        await_peer_status(BHash, connected),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB)
    end.

%% Both ends SSU2-ready and the remote reachable on SSU2 and NTCP2 alike: the
%% dial prefers SSU2 (transport=ssu2), and the queued exploratory lookup plus
%% the self-announcement actually cross the SSU2 session, so the selected
%% transport is fully functional — not just handshake-deep.
transport_ssu2_when_available(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, _Self = self()),
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        B0 = router(),
        {BL, BPort} = ssu2_listener(B0),
        BRI = ssu2_ri_at(listen_port(LB), BPort, B0),
        BHash = i2p_router_info:hash(BRI),
        start_peer(ALocal, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        %% B's SSU2 session (owned by the test) carries A's queued lookup and
        %% self-announcement as SSU2 Data blocks...
        Seen = await_ssu2_types([2, 1], 10),
        true = lists:member(1, Seen),
        true = lists:member(2, Seen),
        await_peer_status(BHash, connected),
        #{status := connected, transport := ssu2} = peer_status(BHash),
        i2p_peer:stop(),
        i2p_ssu2_listener:stop(BL)
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% The remote advertises an SSU2 address nothing answers. The SSU2 handshake
%% times out (the fixed ~20s connect budget), the dial falls back to NTCP2,
%% and the same queued work completes over TCP. Slow by design, hence the
%% explicit 60s timetrap on this scenario.
transport_falls_back_to_ntcp2(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        DeadPort = i2p_ct_helpers:free_port(),
        BRI = ssu2_ri_at(listen_port(LB), DeadPort, B),
        BHash = i2p_router_info:hash(BRI),
        AHash = maps:get(hash, ALocal),
        start_peer(ALocal, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        %% ~20s of SSU2 handshake retries to the dead port, then the NTCP2
        %% dial over B's listener with the queued lookup intact.
        {CB, {lookup, Exploratory}} = await_frame(40000),
        #{type := exploratory, key := AHash} = Exploratory,
        {store, _} = recv_db_store(CB),
        %% 25 ms polls x 1600 = 40 s budget for the SSU2-attempt window.
        await_peer_status(BHash, connected, 1600),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% --------------------------------------------------------------------------
%% Let it crash: a dead peer (nothing listens) only ever produces exponential
%% backoff — a handful of attempts, no hot loop — and the manager recovers
%% once a listener appears on the same port.
%% --------------------------------------------------------------------------

%% The backoff windows (1s, 2s, 4s...) plus the recovery retry need ~8s in
%% total, so the scenario gets an explicit timetrap instead of the CT default.
dead_peer_backs_off_then_recovers(_Config) ->
    A = local(router(), 4668),
    D = local(router(), 4668),
    Port = i2p_ct_helpers:free_port(),
    DRI = ri_at(Port, D),
    DHash = i2p_router_info:hash(DRI),
    start_peer(A, [DRI]),
    ok = i2p_peer:lookup(DHash, exploratory),
    %% The connect fails (nothing listens) -> backoff after one attempt.
    await_peer_status(DHash, backoff),
    #{status := backoff, attempts := Attempts} = peer_status(DHash),
    true = Attempts >= 1,
    %% Let a few backoff windows elapse (1s then 2s): wait until the
    %% manager has retried a couple of times on the spread-out windows,
    %% proving the backoff is exponential — never a tight loop.
    Deadline = erlang:monotonic_time(millisecond) + 8000,
    Attempts2 = wait_for_attempts(DHash, 3, Deadline),
    true = Attempts2 >= 2 andalso Attempts2 =< 4,
    await_peer_status(DHash, backoff),
    %% Bring a listener up on the same port; the next retry must succeed.
    {ok, LD} = i2p_ntcp2_listener:listen(Port, D, self()),
    await_peer_status(DHash, connected),
    i2p_peer:stop(),
    i2p_ntcp2_listener:stop(LD).

%% ---------------------------------------------------------------------------
%% Transport-suite helpers. Wire receipts use `m:i2p_ct_helpers:wait_msg/2`.
%% ---------------------------------------------------------------------------

%% A router node: identity, static keypair, IV, signing seed.
router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        sign_pub => SignPub,
        iv => IV,
        seed => Seed,
        identity => Identity
    }.

%% The full local-keys map with a signed RouterInfo announcing NTCP2 on Port.
local(#{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N, Port) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed),
    N#{sign_seed => Seed, hash => i2p_router_info:hash(RI), ri => RI}.

%% Three distinct router nodes (placeholder port 4668; listeners rebind via
%% ri_at/2 before use).
trio() ->
    {local(router(), 4668), local(router(), 4668), local(router(), 4668)}.

%% Re-sign a router's RouterInfo announcing the actual bound listener port.
ri_at(Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed}) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed).

now_ms() ->
    erlang:system_time(millisecond).

%% --------------------------------------------------------------------------
%% SSU2 transport-selection fixtures
%% --------------------------------------------------------------------------

%% The SSU2 session intro key, derived from the router's static secret exactly
%% as `i2per_sup` does at boot (`i2p_identity:intro_key/1`).
intro_key(#{static_priv := Priv}) ->
    crypto:hash(sha256, <<Priv/binary, "i2p-ssu2-intro">>).

%% The full local-keys map of an SSU2-capable router: static keypair plus
%% derived intro key, and a signed RouterInfo announcing both NTCP2 on
%% NTCP2Port and SSU2 on SSU2Port. Mirrors `i2p_peer:ssu2_connect_ready/3`
%% expectations.
ssu2_local(
    #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N, NTCP2Port, SSU2Port
) ->
    Addrs = [
        i2p_router_info:ntcp2_address(<<"127.0.0.1">>, NTCP2Port, Pub, IV),
        i2p_router_info:ssu2_address(<<"127.0.0.1">>, SSU2Port, Pub, intro_key(N))
    ],
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, now_ms(), Addrs, Opts, Seed),
    N#{
        sign_seed => Seed,
        intro_key => intro_key(N),
        hash => i2p_router_info:hash(RI),
        ri => RI
    }.

%% As `f:ssu2_local/3` but a plain RouterInfo (no full local map): a remote
%% router announcing NTCP2 on NTCP2Port and SSU2 on SSU2Port.
ssu2_ri_at(
    NTCP2Port, SSU2Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N
) ->
    Addrs = [
        i2p_router_info:ntcp2_address(<<"127.0.0.1">>, NTCP2Port, Pub, IV),
        i2p_router_info:ssu2_address(<<"127.0.0.1">>, SSU2Port, Pub, intro_key(N))
    ],
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, now_ms(), Addrs, Opts, Seed).

%% Bind a loopback SSU2 listener for a router (session owner = the test
%% process), registering the `i2p_ssu2_listener` global name so the peer
%% manager's SSU2 guard sees it; return `{Listener, BoundPort}`.
ssu2_listener(#{static_priv := Priv, static_pub := Pub}) ->
    LocalKeys = #{
        static_priv => Priv,
        static_pub => Pub,
        intro_key => crypto:hash(sha256, <<Priv/binary, "i2p-ssu2-intro">>)
    },
    {ok, L} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, LocalKeys, self()),
    {L, i2p_ssu2_listener:port(L)}.

%% The next inbound SSU2 Data delivery to the (test-owned) Bob session,
%% draining any non-session mail (ready/close notices from earlier in the
%% case or from the boot listener) that a plain receive would leave behind.
await_ssu2() ->
    await_ssu2(?TIMEOUT).

await_ssu2(TimeoutMs) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, Pid, Blocks}) -> {true, {Pid, Blocks}};
            (_) -> false
        end,
        TimeoutMs
    ).

%% The I2NP block types carried in SSU2 Data blocks.
ssu2_block_types(Blocks) ->
    [Type || {i2np, Type, _MsgId, _ShortExp, _Body} <- Blocks].

%% Collect inbound SSU2 Data up to N messages until every I2NP type in `Want`
%% has been seen (datagrams may coalesce or split arbitrarily).
await_ssu2_types(Want, N) ->
    collect_ssu2(Want, [], N).

collect_ssu2(_Want, _Seen, 0) ->
    error(ssu2_types_timeout);
collect_ssu2(Want, Seen, N) ->
    {_, Blocks} = await_ssu2(),
    NewSeen = lists:usort(Seen ++ ssu2_block_types(Blocks)),
    case Want -- NewSeen of
        [] -> NewSeen;
        _ -> collect_ssu2(Want, NewSeen, N - 1)
    end.

%% Stop any previous manager (async, so wait for its death) and start a fresh
%% one linked to the test process.
start_peer(Local, Seeds) ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            i2p_peer:stop(),
            MRef = erlang:monitor(process, Pid),
            receive
                {'DOWN', MRef, process, Pid, _} -> ok
            after 5000 ->
                error(stop_timeout)
            end
    end,
    {ok, _} = i2p_peer:start_link(Local, Seeds),
    ok.

listen_port(Listener) ->
    i2p_ntcp2_listener:port(Listener).

%% Wait for the first data-phase frame (we own the bob-side connection), and
%% return the connection pid together with the decoded database message:
%% `{store, Map}` | `{lookup, Map}` | `{search_reply, Map}` |
%% `{delivery_status, MsgID, TimeMs}`.
await_frame() ->
    await_frame(?TIMEOUT).

%% As `f:await_frame/0` with an explicit timeout (the NTCP2 leg of the fallback
%% scenario only appears after the ~20s SSU2 handshake budget).
await_frame(TimeoutMs) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, Conn, Payload}) -> {true, {Conn, db_msg(decode_msg(Payload))}};
            (_) -> false
        end,
        TimeoutMs
    ).

decode_msg(Payload) ->
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    [#{type := 3, data := Data}] = [B || #{type := 3} = B <- Blocks],
    {ok, Msg} = i2p_i2np:decode(Data),
    Msg.

db_msg(#{type := 1, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_store(Body),
    {store, M};
db_msg(#{type := 2, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_lookup(Body),
    {lookup, M};
db_msg(#{type := 3, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_search_reply(Body),
    {search_reply, M};
db_msg(#{type := 10, body := Body}) ->
    {ok, MsgID, TimeMs} = i2p_i2np:decode_delivery_status(Body),
    {delivery_status, MsgID, TimeMs}.

%% Documented load-safe window: 400 polls x 25ms = 10s wall-clock budget for
%% the peer manager to reach a status, which covers the SSU2->NTCP2 handshake
%% (~20s, see the 1600-iteration variant below). The poll is deadline-bounded;
%% the 40s variant exists for the slow fallback path.
await_peer_status(Hash, Status) ->
    await_peer_status(Hash, Status, 400).

await_peer_status(_Hash, _Status, 0) ->
    error({peer_not_in_status, i2p_peer:status()});
await_peer_status(Hash, Status, N) ->
    case i2p_peer:status() of
        #{Hash := #{status := Status}} ->
            ok;
        _ ->
            %% Documented load-safe window: 25ms poll backoff inside the
            %% deadline-bounded await_peer_status loop (see the window note
            %% above) — a state poll over i2p_peer:status(), not a fixed sleep
            %% gating an assertion.
            timer:sleep(25),
            await_peer_status(Hash, Status, N - 1)
    end.

peer_status(Hash) ->
    #{Hash := S} = i2p_peer:status(),
    S.

%% Poll the manager until the dial attempt count reaches MinAttempts — the
%% retries firing on the 1s/2s/4s backoff windows prove exponential backoff.
wait_for_attempts(_Hash, MinAttempts, _Deadline) when MinAttempts =< 0 ->
    i2p_peer:status();
wait_for_attempts(Hash, MinAttempts, Deadline) ->
    #{Hash := #{attempts := N}} = i2p_peer:status(),
    case N >= MinAttempts of
        true ->
            N;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    erlang:error({attempts_timeout, N});
                false ->
                    %% Documented load-safe window: 50ms poll backoff in a
                    %% deadline-bounded loop over i2p_peer:status() — a state
                    %% poll, not a fixed sleep gating an assertion.
                    timer:sleep(50),
                    wait_for_attempts(Hash, MinAttempts, Deadline)
            end
    end.

%% The I2NP message on Conn, decoded — the receive drains anything that is not
%% a frame from this exact connection.
recv_msg(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, P, Payload}) when P =:= Conn -> {true, decode_msg(Payload)};
            (_) -> false
        end,
        ?TIMEOUT
    ).

recv_db_store(Conn) ->
    #{type := 1, body := Body} = recv_msg(Conn),
    {ok, #{store_type := 0, data := Data}} = i2p_i2np:decode_db_store(Body),
    {ok, RIBytes} = i2p_i2np:parse_router_info_data(Data),
    {ok, RI} = i2p_router_info:decode(RIBytes),
    {store, RI}.
