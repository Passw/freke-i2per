%% Identity persistence tests. The identity file round-trips through
%% disk (generate → load → build_local) and a corrupted file is rejected.

-module(i2p_identity_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TEMP_DIR, "/tmp/i2p_identity_test").

identity_roundtrip_test_() ->
    {setup,
        fun() ->
            file:del_dir_r(?TEMP_DIR),
            file:make_dir(?TEMP_DIR)
        end,
        fun(_) -> file:del_dir_r(?TEMP_DIR) end, [
            fun generates_and_loads/0,
            fun load_reuses_existing/0,
            fun corrupted_file_rejected/0,
            fun build_local_reconstructs_keys/0,
            fun build_local_nonpublished/0,
            fun rebuild_router_info_resigns/0
        ]}.

generates_and_loads() ->
    ?assertMatch(
        {ok, #{
            static_priv := _,
            static_pub := _,
            sign_pub := _,
            sign_seed := _,
            iv := _
        }},
        i2p_identity:ensure_identity(?TEMP_DIR)
    ),
    %% Second call loads the same file.
    {ok, Id1} = i2p_identity:ensure_identity(?TEMP_DIR),
    {ok, Id2} = i2p_identity:ensure_identity(?TEMP_DIR),
    ?assertEqual(Id1, Id2).

load_reuses_existing() ->
    %% Write a known file, load it back.
    {ok, Id1} = i2p_identity:ensure_identity(?TEMP_DIR),
    {ok, Id2} = i2p_identity:ensure_identity(?TEMP_DIR),
    ?assertEqual(maps:get(static_pub, Id1), maps:get(static_pub, Id2)),
    ?assertEqual(maps:get(sign_pub, Id1), maps:get(sign_pub, Id2)),
    ?assertEqual(maps:get(iv, Id1), maps:get(iv, Id2)).

corrupted_file_rejected() ->
    %% A corrupted file is silently replaced by a fresh identity.
    {ok, Original} = i2p_identity:ensure_identity(?TEMP_DIR),
    Path = filename:join(?TEMP_DIR, "identity.bin"),
    file:write_file(Path, <<0, 1, 2, 3>>),
    ?assertMatch({ok, #{static_pub := _}}, i2p_identity:ensure_identity(?TEMP_DIR)),
    {ok, AfterCorruption} = i2p_identity:ensure_identity(?TEMP_DIR),
    %% The new identity must differ from the original.
    ?assertNotEqual(maps:get(static_pub, Original), maps:get(static_pub, AfterCorruption)).

build_local_reconstructs_keys() ->
    {ok, Id} = i2p_identity:ensure_identity(?TEMP_DIR),
    Seed = maps:get(sign_seed, Id),
    Local = i2p_identity:build_local(Id, <<"127.0.0.1">>, 9150, Seed),
    ?assertMatch(
        #{
            static_priv := _,
            static_pub := _,
            hash := _,
            iv := _,
            ri := _
        },
        Local
    ),
    ?assertEqual(maps:get(static_pub, Id), maps:get(static_pub, Local)),
    %% The built RouterInfo must carry a spec-valid router-level caps string.
    ?assert(
        i2p_router_info:validate_caps(
            maps:get(<<"caps">>, i2p_router_info:options(maps:get(ri, Local)))
        )
    ).

build_local_nonpublished() ->
    application:set_env(i2per, ntcp2_published, false),
    application:set_env(i2per, allow_private_host, true),
    try
        {ok, Id} = i2p_identity:ensure_identity(?TEMP_DIR),
        Local = i2p_identity:build_local(
            Id, <<"127.0.0.1">>, 9150, maps:get(sign_seed, Id)
        ),
        ?assertEqual(9150, maps:get(port, Local)),
        ?assertEqual(
            {error, no_reachable_ntcp2},
            i2p_router_info:ntcp2_connector(maps:get(ri, Local))
        ),
        Options = i2p_router_info:options(maps:get(ri, Local)),
        ?assertEqual(<<"UL">>, maps:get(<<"caps">>, Options)),
        [Address] = i2p_router_info:addresses(maps:get(ri, Local)),
        ?assertEqual(false, maps:is_key(<<"host">>, maps:get(options, Address)))
    after
        application:unset_env(i2per, ntcp2_published),
        application:unset_env(i2per, allow_private_host)
    end.

%% Re-signing on the refresh cycle: rebuild_router_info mints a fresh
%% RouterInfo with a new publish timestamp but the same identity/hash, and the
%% result still parses (signature verifies). This is what keeps the router from
%% aging out of peer netDbs. The publish timestamp is injected explicitly so
%% the test never depends on a wall-clock tick (no sleep).
rebuild_router_info_resigns() ->
    {ok, Id} = i2p_identity:ensure_identity(?TEMP_DIR),
    Seed = maps:get(sign_seed, Id),
    T0 = 1_700_000_000_000,
    Local0 = i2p_identity:build_local(Id, <<"192.0.2.10">>, 9150, Seed, T0),
    Hash0 = maps:get(hash, Local0),
    RIBin0 = i2p_router_info:to_binary(maps:get(ri, Local0)),
    ?assertEqual(T0, i2p_router_info:published(maps:get(ri, Local0))),
    Local1 = i2p_identity:rebuild_router_info(Local0, T0 + 1000),
    RIBin1 = i2p_router_info:to_binary(maps:get(ri, Local1)),
    ?assertNotEqual(RIBin0, RIBin1),
    ?assertEqual(Hash0, maps:get(hash, Local1)),
    ?assertEqual(T0 + 1000, i2p_router_info:published(maps:get(ri, Local1))),
    %% Same identity/addresses/options; only the timestamp + signature change.
    ?assertEqual(
        i2p_router_info:identity(maps:get(ri, Local0)),
        i2p_router_info:identity(maps:get(ri, Local1))
    ),
    ?assertEqual(
        i2p_router_info:addresses(maps:get(ri, Local0)),
        i2p_router_info:addresses(maps:get(ri, Local1))
    ),
    ?assertEqual(
        i2p_router_info:options(maps:get(ri, Local0)),
        i2p_router_info:options(maps:get(ri, Local1))
    ),
    %% The fresh RouterInfo still parses under the strict validator.
    ?assertMatch({ok, _}, i2p_router_info:parse(RIBin1)).
