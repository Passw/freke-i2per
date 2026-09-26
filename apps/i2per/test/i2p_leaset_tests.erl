%% Unit tests for the LeaseSet2 structure.
%%
%% Build/sign/decode round-trips, the signature-over-storeType-byte rule,
%% lease and key wire layouts, time-window validation and rejection of
%% truncated / tampered / flagged LeaseSets. Fixtures are real signed
%% LeaseSets built with the same SeedKey pattern as the RouterInfo tests.

-module(i2p_leaset_tests).

-include_lib("eunit/include/eunit.hrl").

-define(STORE_TYPE, 3).
-define(LEASE_SIZE, 40).
-define(SIG_LEN, 64).

%%% --------------------------------------------------------------------------
%%% Build / decode round-trip
%%% --------------------------------------------------------------------------

round_trip_matches_fields_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    NowSec = now_sec(),
    Leases = fixture_leases(2),
    LS = i2p_leaset:build(Identity, NowSec, 7, Leases, Seed),
    Bin = i2p_leaset:to_binary(LS),
    {ok, LS2} = i2p_leaset:decode(Bin),
    ?assertEqual(Identity, i2p_leaset:identity(LS2)),
    ?assertEqual(NowSec, i2p_leaset:published(LS2)),
    ?assertEqual(7, i2p_leaset:expires(LS2)),
    ?assertEqual(0, i2p_leaset:flags(LS2)),
    ?assertEqual(#{}, i2p_leaset:properties(LS2)),
    ?assertEqual(Leases, i2p_leaset:leases(LS2)),
    ?assertEqual(Bin, i2p_leaset:to_binary(LS2)),
    ?assertEqual(i2p_keys:hash(Identity), i2p_leaset:hash(LS2)).

properties_round_trip_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    Properties = #{
        <<"type">> => <<"SAM">>,
        <<"maxTunnels">> => <<"4">>
    },
    LS = i2p_leaset:build(Identity, now_sec(), 1, Properties, [], Seed),
    {ok, LS2} = i2p_leaset:decode(i2p_leaset:to_binary(LS)),
    ?assertEqual(Properties, i2p_leaset:properties(LS2)).

empty_leases_allowed_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 1, [], Seed),
    {ok, LS2} = i2p_leaset:decode(i2p_leaset:to_binary(LS)),
    ?assertEqual([], i2p_leaset:leases(LS2)).

build_rejects_too_many_leases_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    Leases = fixture_leases(17),
    ?assertError(badarg, i2p_leaset:build(Identity, now_sec(), 1, Leases, Seed)).

max_leases_round_trip_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    Leases = fixture_leases(16),
    LS = i2p_leaset:build(Identity, now_sec(), 1, Leases, Seed),
    {ok, LS2} = i2p_leaset:decode(i2p_leaset:to_binary(LS)),
    ?assertEqual(16, length(i2p_leaset:leases(LS2))).

%%% --------------------------------------------------------------------------
%%% Wire layout
%%% --------------------------------------------------------------------------

lease_rows_are_40_bytes_test() ->
    Gateway = rand_hash(),
    TunnelID = 16#1020304,
    EndDate = 16#51F61B40,
    Lease = #{gateway => Gateway, tunnel_id => TunnelID, end_date => EndDate},
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 7, [Lease], Seed),
    Bin = i2p_leaset:to_binary(LS),
    %% the lease row is gateway(32) ‖ tunnelID(4 BE) ‖ endDate(4 BE) = 40 bytes
    ExpectedRow = <<Gateway/binary, TunnelID:32/big, EndDate:32/big>>,
    ?assertEqual(40, byte_size(ExpectedRow)),
    ?assertNotEqual(nomatch, binary:match(Bin, ExpectedRow)),
    {ok, LS2} = i2p_leaset:decode(Bin),
    ?assertEqual([Lease], i2p_leaset:leases(LS2)).

signature_covers_store_type_byte_test() ->
    %% The signature is over store_type ‖ content, so re-verifying against the
    %% raw content without the prepended byte must fail.
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 7, fixture_leases(1), Seed),
    Bin = i2p_leaset:to_binary(LS),
    %% verify the signature over the content WITHOUT the store type byte
    Content = binary:part(Bin, 0, byte_size(Bin) - ?SIG_LEN),
    SignPub = i2p_keys:signing_key(Identity),
    ?assertNot(
        i2p_crypto:ed25519_verify(Content, i2p_leaset:signature(LS), SignPub)
    ),
    %% and over store_type ‖ content it must verify
    ?assert(
        i2p_crypto:ed25519_verify(
            <<?STORE_TYPE:8, Content/binary>>, i2p_leaset:signature(LS), SignPub
        )
    ).

one_x25519_key_emitted_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 7, fixture_leases(1), Seed),
    ?assertEqual(
        [#{enc_type => 4, key => i2p_keys:public_key(Identity)}],
        i2p_leaset:keys(LS)
    ),
    {ok, LS2} = i2p_leaset:decode(i2p_leaset:to_binary(LS)),
    ?assertEqual(i2p_keys:public_key(Identity), hd([K || #{key := K} <- i2p_leaset:keys(LS2)])).

store_type_is_3_test() ->
    ?assertEqual(?STORE_TYPE, i2p_leaset:store_type()).

%%% --------------------------------------------------------------------------
%%% Signature / tamper rejection
%%% --------------------------------------------------------------------------

tampered_content_rejected_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 7, fixture_leases(1), Seed),
    Bin = i2p_leaset:to_binary(LS),
    %% flip a bit in the published timestamp (offset = identity len)
    IdLen = byte_size(i2p_keys:to_binary(Identity)),
    <<Prefix:IdLen/binary, Published:32/big, Rest/binary>> = Bin,
    Tampered = <<Prefix/binary, (Published bxor 1):32/big, Rest/binary>>,
    ?assertEqual({error, bad_signature}, i2p_leaset:decode(Tampered)).

truncated_rejected_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 7, fixture_leases(1), Seed),
    Bin = i2p_leaset:to_binary(LS),
    ?assertEqual({error, too_short}, i2p_leaset:decode(binary:part(Bin, 0, 200))),
    ?assertEqual({error, malformed}, i2p_leaset:decode(binary:part(Bin, 0, byte_size(Bin) - 4))).

garbage_rejected_test() ->
    ?assertMatch({error, _}, i2p_leaset:decode(rand_hash(60))),
    ?assertEqual({error, badarg}, i2p_leaset:decode(not_a_binary)).

unsupported_flags_rejected_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    LS = i2p_leaset:build(Identity, now_sec(), 7, fixture_leases(1), Seed),
    Bin = i2p_leaset:to_binary(LS),
    IdLen = byte_size(i2p_keys:to_binary(Identity)),
    <<Prefix:IdLen/binary, Published:32/big, Expires:16/big, Rest/binary>> = Bin,
    %% set the offline-keys bit (0x01) in the flags
    WithFlag = <<Prefix/binary, Published:32/big, Expires:16/big, 16#01:16/big, Rest/binary>>,
    ?assertEqual({error, {unsupported_flags, 16#01}}, i2p_leaset:decode(WithFlag)).

end_date_truncates_to_32_bits_test() ->
    %% A real ms-since-epoch expiration exceeds 32 bits; like i2pd/Java
    %% (writeInt((int) endDate)) build truncates it, and decode returns the
    %% truncated value.
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    %% > 32 bits
    EndDate = 16#1_51F61B40,
    Lease = #{gateway => rand_hash(), tunnel_id => 1, end_date => EndDate},
    LS = i2p_leaset:build(Identity, now_sec(), 7, [Lease], Seed),
    {ok, LS2} = i2p_leaset:decode(i2p_leaset:to_binary(LS)),
    ?assertEqual([Lease#{end_date => EndDate band 16#FFFFFFFF}], i2p_leaset:leases(LS2)).

%%% --------------------------------------------------------------------------
%%% Time-window validation
%%% --------------------------------------------------------------------------

valid_accepts_fresh_lease_set_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    NowSec = now_sec(),
    LS = i2p_leaset:build(Identity, NowSec, 7, fixture_leases(1), Seed),
    ?assertEqual(ok, i2p_leaset:valid(LS, NowSec)),
    %% still usable right up to the 12-minute threshold past the lifetime
    ?assertEqual(ok, i2p_leaset:valid(LS, NowSec + 7 * 86400 + 12 * 60)).

valid_rejects_from_future_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    NowSec = now_sec(),
    LS = i2p_leaset:build(Identity, NowSec + 2 * 60 + 1, 7, fixture_leases(1), Seed),
    ?assertEqual({error, from_future}, i2p_leaset:valid(LS, NowSec)).

valid_rejects_expired_test() ->
    SeedKey = new_seed_key(),
    {Identity, Seed} = identity_seed(SeedKey),
    NowSec = now_sec(),
    LS = i2p_leaset:build(Identity, NowSec, 1, fixture_leases(1), Seed),
    ?assertEqual(ok, i2p_leaset:valid(LS, NowSec + 86400 + 12 * 60)),
    ?assertEqual({error, expired}, i2p_leaset:valid(LS, NowSec + 86400 + 12 * 60 + 1)).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

now_sec() ->
    erlang:system_time(second).

rand_hash() ->
    rand_hash(32).

rand_hash(N) ->
    crypto:strong_rand_bytes(N).

%% {RouterInfo-style SeedKey}: {{SPub, Seed}, {CPub, _}} so the signing seed
%% and the identity's public keys come from the same key pair.
new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, rand_hash()}}.

identity_seed({{SPub, Seed}, {CPub, _}}) ->
    {i2p_keys:from_keys(CPub, SPub), Seed}.

fixture_leases(N) ->
    [
        #{
            gateway => rand_hash(),
            tunnel_id => N + 1,
            end_date => (now_sec() * 1000 + 60 * 1000) band 16#FFFFFFFF
        }
     || _ <- lists:seq(1, N)
    ].
