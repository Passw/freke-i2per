%% Floodfill replication-outbox tests that use a live NetDb process.
%%
%% `replication_outbox/5` selects the closest eligible floodfills from the
%% stored NetDb, excluding self and the sender. The cases assert the computed
%% outbox content and wire messages rather than process-table state. Election
%% and capability wiring remain in the focused EUnit tests.

-module(i2p_floodfill_SUITE).

-export([all/0, suite/0, init_per_testcase/2]).

-export([
    outbox_targets_exclude_self_and_sender/1,
    outbox_lease_set_store_type/1
]).

%% I2NP DatabaseStore message type (see i2p_i2np:db_store/5).
-define(I2NP_DB_STORE, 1).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        outbox_targets_exclude_self_and_sender,
        outbox_lease_set_store_type
    ].

%% Run against a standalone NetDb srv: stop any i2per app a previous suite
%% left running (it owns the same registered name), so every case exercises
%% the acquire-or-reuse start branch against a clean process.
init_per_testcase(_Case, Config) ->
    _ = application:stop(i2per),
    Config.

%% With 5 eligible floodfills seeded and 2 excluded (self + originator),
%% exactly the 3 closest remain as replication targets.
outbox_targets_exclude_self_and_sender(_Config) ->
    Pid = acquire_netdb(),
    try
        application:set_env(i2per, floodfill, true),
        Now = erlang:system_time(millisecond),
        Fixtures = [fixture_floodfill(Now) || _ <- lists:seq(1, 5)],
        lists:foreach(
            fun({RI, _}) -> added = i2p_netdb_srv:store(RI, Now) end,
            Fixtures
        ),
        [OurRI, SenderRI | _] = [RI || {RI, _} <- Fixtures],
        OurHash = i2p_router_info:hash(OurRI),
        SenderHash = i2p_router_info:hash(SenderRI),
        Key = crypto:strong_rand_bytes(32),
        Data = crypto:strong_rand_bytes(64),
        Outbox = i2p_floodfill:replication_outbox(0, Key, Data, OurHash, SenderHash),
        %% replication targets: the 3 closest eligible floodfills, never
        %% ourselves or the originator
        3 = length(Outbox),
        TargetHashes = [T || {T, _} <- Outbox],
        false = lists:member(OurHash, TargetHashes),
        false = lists:member(SenderHash, TargetHashes),
        %% each entry is a DatabaseStore message carrying the stored RouterInfo
        lists:foreach(
            fun({_Target, Msg}) ->
                #{type := ?I2NP_DB_STORE, body := Body} = Msg,
                {ok, Store} = i2p_i2np:decode_db_store(Body),
                assert_router_store(Key, Data, Store)
            end,
            Outbox
        ),
        ok
    after
        teardown_netdb(Pid),
        application:unset_env(i2per, floodfill)
    end.

%% Store type 1 (LeaseSet): self is both the originator and the exclusion
%% key, so the only remaining eligible floodfill is the other fixture — and
%% the forwarded message is a LeaseSet DatabaseStore.
outbox_lease_set_store_type(_Config) ->
    Pid = acquire_netdb(),
    try
        application:set_env(i2per, floodfill, true),
        Now = erlang:system_time(millisecond),
        {OurRI, _} = fixture_floodfill(Now),
        {OtherRI, _} = fixture_floodfill(Now),
        added = i2p_netdb_srv:store(OurRI, Now),
        added = i2p_netdb_srv:store(OtherRI, Now),
        OurHash = i2p_router_info:hash(OurRI),
        OtherHash = i2p_router_info:hash(OtherRI),
        Key = crypto:strong_rand_bytes(32),
        Data = crypto:strong_rand_bytes(64),
        [{Target, Msg}] = i2p_floodfill:replication_outbox(1, Key, Data, OurHash, OurHash),
        OtherHash = Target,
        #{type := ?I2NP_DB_STORE, body := Body} = Msg,
        {ok, Store} = i2p_i2np:decode_db_store(Body),
        #{key := Key, store_type := 1, reply_token := 0, reply := undefined, data := Data} = Store,
        ok
    after
        teardown_netdb(Pid),
        application:unset_env(i2per, floodfill)
    end.

%% A RouterInfo store must round-trip the exact key/data and carry a zero
%% reply token with no reply tunnel: replication targets are not expected to
%% acknowledge (i2p_floodfill:replication_outbox/5 documentation contract).
assert_router_store(Key, Data, Store) ->
    #{key := Key, store_type := 0, reply_token := 0, reply := undefined, data := Data} = Store,
    ok.

%% --------------------------------------------------------------------------
%% Standalone NetDb srv plumbing (mirrors i2p_netdb_srv_SUITE)
%% --------------------------------------------------------------------------

%% Acquire-or-reuse: a left-behind instance from another suite is adopted, so
%% a case never races a dying process's unregister.
acquire_netdb() ->
    case whereis(i2p_netdb_srv) of
        undefined ->
            {ok, P} = i2p_netdb_srv:start_link(),
            P;
        Existing ->
            Existing
    end.

%% Only tear down an instance we own; the app supervisor is stopped in
%% init_per_testcase, so nothing else races the shutdown.
teardown_netdb(Pid) ->
    case whereis(i2p_netdb_srv) of
        Pid ->
            unlink(Pid),
            exit(Pid, shutdown);
        _ ->
            ok
    end.

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

%% {RouterInfo, SeedKey} — an eligible floodfill: version >= 0.9.62, caps
%% `Of`, and a published publicly-routable IPv4 address.
fixture_floodfill(Timestamp) ->
    SeedKey = new_seed_key(),
    {build_from(SeedKey, Timestamp, <<"0.9.74">>, <<"Of">>, <<"192.0.2.10">>), SeedKey}.

new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, crypto:strong_rand_bytes(32)}}.

build_from(SeedKey, Timestamp, Version, Caps, Host) ->
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Addr = i2p_router_info:ntcp2_address(
        Host, 4668, crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(16)
    ),
    Opts = maps:merge(
        #{<<"netId">> => <<"2">>, <<"router.version">> => Version},
        caps_map(Caps)
    ),
    i2p_router_info:build(Identity, Timestamp, [Addr], Opts, Seed).

caps_map(undefined) -> #{};
caps_map(Caps) -> #{<<"caps">> => Caps}.
