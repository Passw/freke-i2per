%% Exploratory lookup-pool tests. The cases cover pool top-up, completed
%% builds, lookup selection and client-pool fallback, client selection ignoring
%% the exploratory pool, and inbound data delivery.
%%
%% Each case owns the application and tunnel-manager lifecycle. Tests use the
%% public status and selection APIs. Narrow `sys:replace_state/2` fixtures seed
%% pending or active maps when the encrypted build path is outside the case's
%% subject.

-module(i2p_tunnel_srv_exploratory_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    tick_builds_lookup_pool/1,
    tick_no_duplicate/1,
    outbound_completes_into_exploratory_map/1,
    inbound_completes_into_exploratory_in_map/1,
    pick_lookup_prefers_exploratory_then_falls_back/1,
    pick_client_ignores_exploratory/1,
    exploratory_inbound_data_delivery/1
]).

-include_lib("eunit/include/eunit.hrl").

-define(APP, i2per).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        tick_builds_lookup_pool,
        tick_no_duplicate,
        outbound_completes_into_exploratory_map,
        inbound_completes_into_exploratory_in_map,
        pick_lookup_prefers_exploratory_then_falls_back,
        pick_client_ignores_exploratory,
        exploratory_inbound_data_delivery
    ].

%% The cases need the full app for the NetDb service (store_binary/find); the
%% tunnel manager is started per case in the body. App stop in
%% end_per_testcase leaves a clean envelope — fresh netdb and no tunnel_pool
%% env — for the next case.
init_per_testcase(_Case, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    Config.

end_per_testcase(_Case, _Config) ->
    ok = application:unset_env(?APP, tunnel_pool),
    application:stop(?APP),
    ok.

%%%%%%%%% Exploratory tick builds its own pool %%%%%%%%%

tick_builds_lookup_pool(_Config) ->
    ok = application:set_env(
        ?APP,
        tunnel_pool,
        #{outbound => 1, inbound => 1, exploratory => 1, exploratory_hops => 1}
    ),
    {Pid, _Local} = start_tunnel_srv(),
    try
        seed_netdb(3),
        %% No active inbound: both arms queue their inbound builds
        i2p_tunnel_srv ! pool_tick,
        #{pending_in := PendingIn} = i2p_tunnel_srv:status(),
        {ExploratoryPend, ClientPend} = split_pool(PendingIn),
        ?assertEqual(1, maps:size(ExploratoryPend)),
        ?assertEqual(1, maps:size(ClientPend)),
        [ExpBuild] = maps:values(ExploratoryPend),
        ?assertEqual(exploratory, maps:get(pool, ExpBuild)),
        ?assertEqual(1, length(maps:get(router_hashes, ExpBuild))),
        [ClientBuild] = maps:values(ClientPend),
        ?assertEqual(3, length(maps:get(router_hashes, ClientBuild)))
    after
        stop_tunnel_srv(Pid)
    end.

%% A second tick must not duplicate the in-flight exploratory build.
tick_no_duplicate(_Config) ->
    ok = application:set_env(
        ?APP,
        tunnel_pool,
        #{outbound => 1, inbound => 1, exploratory => 1, exploratory_hops => 1}
    ),
    {Pid, _Local} = start_tunnel_srv(),
    try
        seed_netdb(3),
        i2p_tunnel_srv ! pool_tick,
        i2p_tunnel_srv ! pool_tick,
        #{pending_in := PendingIn} = i2p_tunnel_srv:status(),
        {ExploratoryPend, _} = split_pool(PendingIn),
        ?assertEqual(1, maps:size(ExploratoryPend))
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Completed builds land in the exploratory maps %%%%%%%%%

%% Completion requires a pending build record under a fresh MsgID with the hop
%% keys the encrypted records were sealed to. The server's real build path
%% picks those hops itself and sends the STB over the wire; re-deriving that
%% seam is not this case's subject, so the pending record is injected.
outbound_completes_into_exploratory_map(_Config) ->
    [LocalRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    AllRouters = [LocalRouter | HopRouters],
    lists:foreach(
        fun(R) ->
            RI = maps:get(ri, R),
            NowMs = erlang:system_time(millisecond),
            {ok, _} = i2p_netdb_srv:store_binary(i2p_router_info:to_binary(RI), NowMs)
        end,
        AllRouters
    ),
    {Pid, Local} = start_tunnel_srv(LocalRouter),
    LocalHash = maps:get(hash, Local),
    try
        %% Creator builds a 2-hop exploratory outbound (OBEP at position 1)
        HopHashes = [maps:get(hash, R) || R <- HopRouters],
        TunnelIds = [800, 801],
        ObepPos = 1,
        Plaintexts = [
            i2p_tunnel:build_request_record(800, 801, lists:nth(2, HopHashes), #{}),
            i2p_tunnel:build_request_record(801, 0, LocalHash, #{endpoint => true})
        ],
        HopDescs = [
            #{
                eph_priv => EPriv,
                hop_pub => maps:get(static_pub, R),
                id_hash => maps:get(hash, R)
            }
         || {R, {_EPub, EPriv}} <-
                lists:zip(
                    lists:sublist(HopRouters, 2),
                    [i2p_crypto:x25519_keygen() || _ <- lists:seq(1, 2)]
                )
        ],
        {EncRecords, CreatorHops} =
            i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, ObepPos),

        %% Hops process and seal in build order
        FinalRecords =
            lists:foldl(
                fun(Router, Records) ->
                    {ok, Info} = i2p_tunnel:process_short_tunnel_build(
                        maps:get(static_priv, Router),
                        maps:get(static_pub, Router),
                        maps:get(hash, Router),
                        Records
                    ),
                    i2p_tunnel:apply_build_reply(Info, 0, Records)
                end,
                EncRecords,
                lists:sublist(HopRouters, 2)
            ),

        %% A pending exploratory build completes under its message ID
        MsgID = crypto:strong_rand_bytes(4),
        ok = inject_pending_build(MsgID, #{
            tunnel_ids => TunnelIds,
            router_hashes => lists:sublist(HopHashes, 2),
            hop_keys => CreatorHops,
            pool => exploratory,
            timer_ref => make_ref()
        }),
        OTBRMMsg = i2p_i2np:outbound_tunnel_build_reply(FinalRecords),
        FirstHopHash = hd(HopHashes),
        i2p_tunnel_srv !
            {i2np, self(), FirstHopHash, OTBRMMsg#{msg_id := MsgID}},

        %% The tunnel is an ACTIVE EXPLORATORY outbound, not a client one
        #{pending := Pending, tunnels := Tunnels, exploratory := Exploratory} =
            i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending),
        ?assertEqual(#{}, Tunnels),
        ?assertEqual(1, maps:size(Exploratory)),
        [{_TunID, Entry}] = maps:to_list(Exploratory),
        ?assertEqual(lists:sublist(HopHashes, 2), maps:get(router_hashes, Entry)),
        ?assertEqual(TunnelIds, maps:get(tunnel_ids, Entry))
    after
        stop_tunnel_srv(Pid)
    end.

%% Same seam for the inbound direction: the sealed STB returns through a fake
%% terminal record for a 1-hop exploratory inbound; the pending_in record is
%% injected so the returned STB can be matched under its MsgID.
inbound_completes_into_exploratory_in_map(_Config) ->
    [LocalRouter, HopRouter] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(
        fun(R) ->
            RI = maps:get(ri, R),
            NowMs = erlang:system_time(millisecond),
            {ok, _} = i2p_netdb_srv:store_binary(i2p_router_info:to_binary(RI), NowMs)
        end,
        [LocalRouter, HopRouter]
    ),
    {Pid, Local} = start_tunnel_srv(LocalRouter),
    LocalHash = maps:get(hash, Local),
    HopHash = maps:get(hash, HopRouter),
    try
        %% 1-hop exploratory inbound: IBGW points back at us, fake record last
        TunnelIds = [600, 601],
        Plaintexts = [
            i2p_tunnel:build_request_record(600, 0, LocalHash, #{gateway => true}),
            crypto:strong_rand_bytes(154)
        ],
        {_, EPriv} = i2p_crypto:x25519_keygen(),
        RealDescs = [
            #{eph_priv => EPriv, hop_pub => maps:get(static_pub, HopRouter), id_hash => HopHash}
        ],
        FakeDesc = #{
            eph_priv => element(2, i2p_crypto:x25519_keygen()),
            hop_pub => maps:get(static_pub, LocalRouter),
            id_hash => LocalHash
        },
        {EncRecords, AllKeys} =
            i2p_ecies:encrypt_build_records(RealDescs ++ [FakeDesc], Plaintexts, none),
        {HopKeys, [_FakeKey]} = lists:split(1, AllKeys),

        {ok, Info} = i2p_tunnel:process_short_tunnel_build(
            maps:get(static_priv, HopRouter),
            maps:get(static_pub, HopRouter),
            HopHash,
            EncRecords
        ),
        FinalRecords = i2p_tunnel:apply_build_reply(Info, 0, EncRecords),

        MsgID = crypto:strong_rand_bytes(4),
        ok = inject_pending_inbound(MsgID, #{
            tunnel_ids => TunnelIds,
            router_hashes => [HopHash],
            hop_keys => HopKeys,
            pool => exploratory,
            timer_ref => make_ref()
        }),
        ReturnedMsg = i2p_i2np:short_tunnel_build(FinalRecords),
        i2p_tunnel_srv ! {i2np, self(), HopHash, ReturnedMsg#{msg_id := MsgID}},

        #{pending_in := PendingIn, inbound := Inbound, exploratory_in := ExploratoryIn} =
            i2p_tunnel_srv:status(),
        ?assertEqual(#{}, PendingIn),
        ?assertEqual(#{}, Inbound),
        ?assertEqual(1, maps:size(ExploratoryIn)),
        [{601, Entry}] = maps:to_list(ExploratoryIn),
        ?assertEqual(TunnelIds, maps:get(tunnel_ids, Entry)),
        ?assertEqual([HopHash], maps:get(router_hashes, Entry))
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Lookup picks prefer exploratory, fall back to client %%%%%%%%%

%% The pick preference is a pure read over the pool maps' contents; the maps
%% are injected because building real tunnels with their random key material is
%% not this case's subject.
pick_lookup_prefers_exploratory_then_falls_back(_Config) ->
    {Pid, _Local} = start_tunnel_srv(),
    try
        %% Client pools carry a 3-hop tunnel; the exploratory pool the 2-hop one
        ClientOut = entry(901, 3),
        ok = inject_outbound_entry(901, ClientOut),
        ExpOut = entry(902, 2),
        ok = inject_exploratory_outbound(902, ExpOut),
        {ok, 902, ExpOut} = i2p_tunnel_srv:pick_lookup_outbound(),
        {ok, 902, ExpOut} = i2p_tunnel_srv:pick_exploratory_out(),

        ClientIn = entry(911, 3),
        ok = inject_inbound_entry(911, ClientIn),
        ExpIn = entry(912, 2),
        ok = inject_exploratory_inbound(912, ExpIn),
        {ok, 912, ExpIn} = i2p_tunnel_srv:pick_lookup_inbound(),
        {ok, 912, ExpIn} = i2p_tunnel_srv:pick_exploratory_in(),

        %% Drop the exploratory tunnels: lookup picks fall back to client
        ok = remove_exploratory(exploratory),
        ok = remove_exploratory(exploratory_in),
        {ok, 901, ClientOut} = i2p_tunnel_srv:pick_lookup_outbound(),
        {ok, 911, _} = i2p_tunnel_srv:pick_lookup_inbound(),
        ?assertEqual(error, i2p_tunnel_srv:pick_exploratory_out()),
        ?assertEqual(error, i2p_tunnel_srv:pick_exploratory_in())
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Client picks ignore the exploratory pools %%%%%%%%%

pick_client_ignores_exploratory(_Config) ->
    {Pid, _Local} = start_tunnel_srv(),
    try
        ok = inject_exploratory_outbound(902, entry(902, 2)),
        ok = inject_exploratory_inbound(912, entry(912, 2)),
        ?assertEqual(error, i2p_tunnel_srv:pick_outbound()),
        ?assertEqual(error, i2p_tunnel_srv:pick_inbound()),
        %% status() exposes the exploratory pools behind their own keys
        #{tunnels := T, exploratory := Exp, exploratory_in := ExpIn} =
            i2p_tunnel_srv:status(),
        ?assertEqual(#{}, T),
        ?assertEqual(1, maps:size(Exp)),
        ?assertEqual(1, maps:size(ExpIn))
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Data delivered on an exploratory inbound endpoint dispatches %%%%%%%%%

%% The active inbound's layer keys are injected because the test must encrypt
%% the garlic clove through exactly those keys to prove delivery.
exploratory_inbound_data_delivery(_Config) ->
    LocalRouter = make_router(),
    {Pid, _Local} = start_tunnel_srv(LocalRouter),
    try
        %% Active exploratory inbound tunnel with a known single layer
        RecvID = 700,
        LK = crypto:strong_rand_bytes(32),
        IVK = crypto:strong_rand_bytes(32),
        Layers = [#{layer_key => LK, iv_key => IVK}],
        ok = inject_exploratory_inbound(RecvID, #{
            tunnel_ids => [701, RecvID],
            router_hashes => [crypto:strong_rand_bytes(32)],
            layers => Layers,
            frag_map => #{},
            built_at => erlang:system_time(second)
        }),

        %% A DatabaseStore clove wrapped to OUR static key, framed for the
        %% exploratory inbound gateway
        RiRouter = make_router(),
        RiBin = i2p_router_info:to_binary(maps:get(ri, RiRouter)),
        RiHash = i2p_router_info:hash(maps:get(ri, RiRouter)),
        StoreBody = <<RiHash/binary, 0:8, 0:32/big, RiBin/binary>>,
        Clove = #{
            delivery => local,
            type => 1,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 300,
            data => StoreBody
        },
        GarlicMsg = i2p_garlic:wrap_router([Clove], maps:get(static_pub, LocalRouter)),
        StdMsg = i2p_i2np:encode_std(GarlicMsg#{expiration_ms => 60000}),

        {ok, Frame1, _} = i2p_tunnel:gateway(701, local, undefined, StdMsg, #{frag_map => #{}}),
        <<_:32/big, Rest0/binary>> = Frame1,
        Wire = i2p_tunnel:encrypt_layer(
            <<RecvID:32/big, Rest0/binary>>,
            LK,
            IVK
        ),
        DataMsg = #{
            type => 18,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 60,
            body => Wire
        },
        i2p_tunnel_srv ! {i2np, self(), crypto:strong_rand_bytes(32), DataMsg},
        _ = i2p_tunnel_srv:status(),

        Result = i2p_netdb_srv:find(RiHash),
        ?assertMatch({ok, _}, Result)
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Harness %%%%%%%%%

split_pool(Pending) ->
    maps:fold(
        fun(MsgID, Build, {Exp, Client}) ->
            case maps:get(pool, Build, client) of
                exploratory -> {maps:put(MsgID, Build, Exp), Client};
                client -> {Exp, maps:put(MsgID, Build, Client)}
            end
        end,
        {#{}, #{}},
        Pending
    ).

entry(Base, Hops) ->
    Hashes = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, Hops)],
    #{
        tunnel_ids => [Base + I || I <- lists:seq(0, Hops - 1)],
        router_hashes => Hashes,
        layers => [
            #{layer_key => crypto:strong_rand_bytes(32), iv_key => crypto:strong_rand_bytes(32)}
         || _ <- Hashes
        ],
        built_at => erlang:system_time(second)
    }.

make_router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Port = free_port(),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        iv => IV,
        seed => Seed,
        identity => Identity,
        ri => RI,
        hash => i2p_router_info:hash(RI)
    }.

free_port() ->
    {ok, L} = gen_tcp:listen(0, [{reuseaddr, true}]),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Port.

start_tunnel_srv() ->
    start_tunnel_srv(make_router()).

start_tunnel_srv(Router) ->
    RI = maps:get(ri, Router),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => i2p_router_info:hash(RI),
        iv => maps:get(iv, Router),
        ri => RI
    },
    {ok, Pid} = i2p_tunnel_srv:start_link(Local),
    {Pid, Local}.

stop_tunnel_srv(Pid) ->
    Ref = erlang:monitor(process, Pid),
    i2p_tunnel_srv:stop(),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 ->
        erlang:demonitor(Ref, [flush]),
        erlang:error({tunnel_srv_stop_timeout, Pid})
    end.

%%%%%%%%% Confined state injection %%%%%%%%%

%% `sys:replace_state` is confined to the cases above that seed internal maps
%% whose contents cannot enter through the public interface without forging
%% the server's own build path. Each such case documents why. A leaked
%% registration from a failed case surfaces as `{error, {already_started, _}}`
%% on the next `start_link`, failing it fast — no defensive reset helper.

inject_pending_build(MsgID, Build) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{pending := Pending} = State) ->
        State#{pending := maps:put(MsgID, Build, Pending)}
    end),
    ok.

inject_pending_inbound(MsgID, Build) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{pending_in := Pending} = State) ->
        State#{pending_in := maps:put(MsgID, Build, Pending)}
    end),
    ok.

inject_outbound_entry(TunID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{tunnels := Tunnels} = State) ->
        State#{tunnels := maps:put(TunID, Entry, Tunnels)}
    end),
    ok.

inject_inbound_entry(RecvID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{inbound := Inbound} = State) ->
        State#{inbound := maps:put(RecvID, Entry, Inbound)}
    end),
    ok.

inject_exploratory_outbound(TunID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{exploratory := Exploratory} = State) ->
        State#{exploratory := maps:put(TunID, Entry, Exploratory)}
    end),
    ok.

inject_exploratory_inbound(RecvID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{exploratory_in := ExploratoryIn} = State) ->
        State#{exploratory_in := maps:put(RecvID, Entry, ExploratoryIn)}
    end),
    ok.

remove_exploratory(Key) ->
    sys:replace_state(i2p_tunnel_srv, fun(State) -> State#{Key := #{}} end),
    ok.

seed_netdb(N) ->
    lists:foreach(
        fun(_) ->
            R = make_router(),
            NowMs = erlang:system_time(millisecond),
            {ok, _} =
                i2p_netdb_srv:store_binary(
                    i2p_router_info:to_binary(maps:get(ri, R)), NowMs
                )
        end,
        lists:seq(1, N)
    ).
