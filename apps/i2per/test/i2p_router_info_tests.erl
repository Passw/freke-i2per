%% Structural and round-trip tests for the RouterInfo / RouterAddress /
%% Mapping structures used by the NTCP2 and SSU2 transports.
%%
%% The tests use the published wire structures and exercise the parsers and
%% constructors against deterministic fixtures.
%% They pin the wire layout (cost, expiration, transport style, and options),
%% the Ed25519 signature round-trip, and the validation rejections.

-module(i2p_router_info_tests).

-include_lib("eunit/include/eunit.hrl").

-define(NTCP2_COST, 3).

%%% --------------------------------------------------------------------------
%%% Build / parse round-trip
%%% --------------------------------------------------------------------------

roundtrip_single_address_test() ->
    {Identity, Seed} = test_identity(),
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()),
    RI = build(Identity, Seed, [Addr]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    ?assertEqual(Identity, i2p_router_info:identity(RI)),
    ?assertEqual(i2p_keys:hash(Identity), i2p_router_info:hash(RI)),
    ?assertEqual(1_800_000_000, i2p_router_info:published(RI)),
    ?assertEqual([Addr], i2p_router_info:addresses(RI)),
    ?assertEqual(router_options(), i2p_router_info:options(RI)).

roundtrip_no_addresses_test() ->
    {Identity, Seed} = test_identity(),
    RI = i2p_router_info:build(Identity, 1_800_000_000, [], router_options(), Seed),
    ?assertEqual({error, no_reachable_ntcp2}, i2p_router_info:parse(i2p_router_info:to_binary(RI))).

roundtrip_identity_hash_is_router_hash_test() ->
    {Identity, Seed} = test_identity(),
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()),
    RI = build(Identity, Seed, [Addr]),
    Bin = i2p_router_info:to_binary(RI),
    {ok, RI} = i2p_router_info:parse(Bin),
    %% The parse keeps the exact signed wire bytes.
    ?assertEqual(Bin, i2p_router_info:to_binary(RI)),
    ?assertEqual(32, byte_size(i2p_router_info:hash(RI))).

%% The signature must verify: parse returns ok only when signed by the
%% identity's own signing key.
roundtrip_signature_verified_test() ->
    {Identity, Seed} = test_identity(),
    {_OtherPub, OtherSeed} = i2p_crypto:ed25519_keygen(),
    RI = i2p_router_info:build(Identity, 1_800_000_000, [ntcp2_addr()], router_options(), Seed),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    %% A RouterInfo signed by the wrong key must not parse.
    BadRI = i2p_router_info:build(
        Identity, 1_800_000_000, [ntcp2_addr()], router_options(), OtherSeed
    ),
    ?assertEqual({error, bad_signature}, i2p_router_info:parse(i2p_router_info:to_binary(BadRI))).

signature_tamper_rejected_test() ->
    {Identity, Seed} = test_identity(),
    RI = build(Identity, Seed, [ntcp2_addr()]),
    Bin = i2p_router_info:to_binary(RI),
    ?assertEqual(
        {error, bad_signature}, i2p_router_info:parse(flip_byte(Bin, byte_size(Bin) div 2))
    ).

body_tamper_rejected_test() ->
    {Identity, Seed} = test_identity(),
    RI = build(Identity, Seed, [ntcp2_addr()]),
    Bin = i2p_router_info:to_binary(RI),
    ?assertEqual({error, bad_signature}, i2p_router_info:parse(flip_byte(Bin, 400))).

%%% --------------------------------------------------------------------------
%%% Wire layout
%%% --------------------------------------------------------------------------

%% cost=3 (published NTCP2), expiration=0, style "NTCP2", then a Mapping.
ntcp2_address_wire_layout_test() ->
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()),
    Bin = i2p_router_info:encode_address(Addr),
    <<Cost:8, Expiration:64/big, StyleLen:8, Style:StyleLen/binary, _Mapping/binary>> = Bin,
    ?assertEqual(?NTCP2_COST, Cost),
    ?assertEqual(0, Expiration),
    ?assertEqual(<<"NTCP2">>, Style),
    ?assertEqual(1 + 8 + 1 + 5, byte_size(Bin) - byte_size(mapping_of(Bin))),
    %% decode back
    {ok, Addr} = i2p_router_info:parse_address(Bin).

%% The NTCP2 options are host, i (16-byte IV, I2P Base64), port, s (32-byte
%% static key, I2P Base64), v=2 and caps (4 for IPv4) — matching i2pd's
%% WriteToStream.
ntcp2_address_options_test() ->
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()),
    #{options := Options} = Addr,
    ?assertEqual(<<"192.0.2.10">>, maps:get(<<"host">>, Options)),
    ?assertEqual(<<"4668">>, maps:get(<<"port">>, Options)),
    ?assertEqual(<<"2">>, maps:get(<<"v">>, Options)),
    ?assertEqual(<<"4">>, maps:get(<<"caps">>, Options)),
    IV = i2p_keys:decode_b64(maps:get(<<"i">>, Options)),
    Static = i2p_keys:decode_b64(maps:get(<<"s">>, Options)),
    ?assertEqual(iv(), IV),
    ?assertEqual(static_key(), Static),
    ?assertEqual(24, byte_size(maps:get(<<"i">>, Options))),
    ?assertEqual(44, byte_size(maps:get(<<"s">>, Options))).

%% An IPv6 host derives the `caps` flag 6.
ntcp2_address_ipv6_caps_test() ->
    Addr = i2p_router_info:ntcp2_address(<<"2001:db8::1">>, 4668, static_key(), iv()),
    #{options := Options} = Addr,
    ?assertEqual(<<"6">>, maps:get(<<"caps">>, Options)).

ntcp2_nonpublished_address_roundtrip_test() ->
    {Identity, Seed} = test_identity(),
    Addr = i2p_router_info:ntcp2_nonpublished_address(ipv4, static_key()),
    ?assertEqual(14, maps:get(cost, Addr)),
    ?assertEqual(
        #{<<"caps">> => <<"4">>, <<"s">> => i2p_keys:encode_b64(static_key()), <<"v">> => <<"2">>},
        maps:get(options, Addr)
    ),
    RI = build(Identity, Seed, [Addr]),
    {ok, Parsed} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    ?assertEqual([Addr], i2p_router_info:addresses(Parsed)),
    ?assertEqual({error, no_reachable_ntcp2}, i2p_router_info:ntcp2_connector(Parsed)).

%% The SSU2 `caps` option advertises the family letter plus the `B`
%% peer-test capability for both host families.
ssu2_address_caps_test() ->
    Addr = i2p_router_info:ssu2_address(<<"192.0.2.10">>, 4668, static_key(), intro_key()),
    #{options := Options} = Addr,
    ?assertEqual(<<"4B">>, maps:get(<<"caps">>, Options)).

ssu2_address_ipv6_caps_test() ->
    Addr = i2p_router_info:ssu2_address(<<"2001:db8::1">>, 4668, static_key(), intro_key()),
    #{options := Options} = Addr,
    ?assertEqual(<<"6B">>, maps:get(<<"caps">>, Options)).

%% A published SSU2 address round-trips through parse, and `B` in `caps`
%% surfaces as the `peer_test` capability for Bob's Charlie selection.
ssu2_address_options_reports_peer_test_test() ->
    {Identity, Seed} = test_identity(),
    Addr = i2p_router_info:ssu2_address(<<"192.0.2.10">>, 4668, static_key(), intro_key()),
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
    ?assertEqual(true, maps:get(peer_test, Opts)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(host, Opts)),
    ?assertEqual(4668, maps:get(port, Opts)),
    ?assertEqual(static_key(), maps:get(static_key, Opts)).

%% An address without a `caps` option is still usable, but not a
%% peer-test participant.
ssu2_address_options_peer_test_absent_test() ->
    {Identity, Seed} = test_identity(),
    Addr = #{
        transport => <<"SSU2">>,
        cost => 5,
        expiration => 0,
        options => #{
            <<"host">> => <<"192.0.2.10">>,
            <<"port">> => <<"4668">>,
            <<"s">> => i2p_keys:encode_b64(static_key()),
            <<"i">> => i2p_keys:encode_b64(intro_key()),
            <<"v">> => <<"2">>
        }
    },
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
    ?assertEqual(false, maps:get(peer_test, Opts)).

%% A published SSU2 address parses as published with no introducers and
%% no `C` capability.
ssu2_address_options_published_defaults_test() ->
    {Identity, Seed} = test_identity(),
    Addr = i2p_router_info:ssu2_address(<<"192.0.2.10">>, 4668, static_key(), intro_key()),
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
    ?assertEqual(true, maps:get(published, Opts)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(host, Opts)),
    ?assertEqual(4668, maps:get(port, Opts)),
    ?assertEqual([], maps:get(introducers, Opts)),
    ?assertEqual(false, maps:get(introducer, Opts)).

%% The `C` caps letter (SSU2 introducer capability) surfaces separately
%% from the `B` peer-test letter.
ssu2_address_options_caps_c_test() ->
    {Identity, Seed} = test_identity(),
    Addr = #{
        transport => <<"SSU2">>,
        cost => 5,
        expiration => 0,
        options => #{
            <<"host">> => <<"192.0.2.10">>,
            <<"port">> => <<"4668">>,
            <<"s">> => i2p_keys:encode_b64(static_key()),
            <<"i">> => i2p_keys:encode_b64(intro_key()),
            <<"v">> => <<"2">>,
            <<"caps">> => <<"BC">>
        }
    },
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
    ?assertEqual(true, maps:get(peer_test, Opts)),
    ?assertEqual(true, maps:get(introducer, Opts)).

%% A firewalled router publishes a non-published SSU2 address: no host/port,
%% family-only caps, and its introducers as indexed ih/itag/iexp options that
%% round-trip through encode and parse.
ssu2_introducer_address_roundtrip_test() ->
    {Identity, Seed} = test_identity(),
    [Intro1, Intro2, Intro3] = test_introducers(),
    Addr = i2p_router_info:ssu2_introducer_address(
        <<"192.0.2.55">>, static_key(), intro_key(), [Intro1, Intro2, Intro3]
    ),
    #{transport := <<"SSU2">>, cost := 14, options := Options} = Addr,
    ?assertEqual(<<"4">>, maps:get(<<"caps">>, Options)),
    ?assertEqual(false, maps:is_key(<<"host">>, Options)),
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
    ?assertEqual(false, maps:get(published, Opts)),
    ?assertEqual(undefined, maps:get(host, Opts)),
    ?assertEqual(undefined, maps:get(port, Opts)),
    ?assertEqual(false, maps:get(peer_test, Opts)),
    ?assertEqual(false, maps:get(introducer, Opts)),
    ?assertEqual(
        [Intro1, Intro2, Intro3],
        maps:get(introducers, Opts)
    ).

%% The exact option keys land as i2pd writes them: `ih<i>`/`itag<i>`/`iexp<i>`
%% base64 hash, decimal tag, decimal Unix-second expiry.
ssu2_introducer_address_exact_options_test() ->
    [Intro1 | _] = Intros = test_introducers(),
    Hash = maps:get(hash, Intro1),
    Addr = i2p_router_info:ssu2_introducer_address(
        <<"192.0.2.55">>, static_key(), intro_key(), Intros
    ),
    #{cost := 14, options := Options} = Addr,
    ?assertEqual(<<"4">>, maps:get(<<"caps">>, Options)),
    ?assertEqual(i2p_keys:encode_b64(Hash), maps:get(<<"ih0">>, Options)),
    ?assertEqual(<<"7">>, maps:get(<<"itag0">>, Options)),
    ?assertEqual(<<"900">>, maps:get(<<"iexp0">>, Options)),
    ?assertEqual(false, maps:is_key(<<"iexp2">>, Options)).

%% An introducer without an expiry is published without the `iexp` option and
%% parses back with `exp` unset.
ssu2_introducer_address_no_expiry_test() ->
    {Identity, Seed} = test_identity(),
    Intro = #{hash => hash2(), tag => 42},
    Addr = i2p_router_info:ssu2_introducer_address(
        <<"2001:db8::1">>, static_key(), intro_key(), [Intro]
    ),
    #{options := Options} = Addr,
    ?assertEqual(<<"6">>, maps:get(<<"caps">>, Options)),
    ?assertEqual(false, maps:is_key(<<"iexp0">>, Options)),
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
    ?assertEqual([Intro], maps:get(introducers, Opts)).

%% More than `?MAX_INTRODUCERS` introducers are rejected by the builder.
ssu2_introducer_address_rejects_too_many_test() ->
    Intros = test_introducers() ++ [#{hash => hash2(), tag => 5, exp => 5}],
    ?assertError(
        badarg,
        i2p_router_info:ssu2_introducer_address(
            <<"192.0.2.55">>, static_key(), intro_key(), Intros
        )
    ).

%% A non-published address with no introducers is unusable.
ssu2_introducer_address_needs_introducers_test() ->
    {Identity, Seed} = test_identity(),
    Addr = i2p_router_info:ssu2_introducer_address(
        <<"192.0.2.55">>, static_key(), intro_key(), []
    ),
    RI = build(Identity, Seed, [Addr, ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    ?assertEqual(error, i2p_router_info:ssu2_address_options(RI)).

%% Options keys are serialized in sorted order (caps, host, i, port, s, v).
ntcp2_address_sorted_options_test() ->
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()),
    #{options := Options} = Addr,
    Pairs = <<
        4:8,
        <<"caps">>/binary,
        $=,
        1:8,
        <<"4">>/binary,
        $;,
        4:8,
        <<"host">>/binary,
        $=,
        10:8,
        <<"192.0.2.10">>/binary,
        $;,
        1:8,
        <<"i">>/binary,
        $=,
        24:8,
        (i2p_keys:encode_b64(iv()))/binary,
        $;,
        4:8,
        <<"port">>/binary,
        $=,
        4:8,
        <<"4668">>/binary,
        $;,
        1:8,
        <<"s">>/binary,
        $=,
        44:8,
        (i2p_keys:encode_b64(static_key()))/binary,
        $;,
        1:8,
        <<"v">>/binary,
        $=,
        1:8,
        <<"2">>/binary,
        $;
    >>,
    ?assertEqual(
        <<(byte_size(Pairs)):16/big, Pairs/binary>>, i2p_router_info:encode_mapping(Options)
    ).

%%% --------------------------------------------------------------------------
%%% Mapping
%%% --------------------------------------------------------------------------

mapping_roundtrip_test() ->
    Map = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"46">>
    },
    {ok, Map} = i2p_router_info:parse_mapping(i2p_router_info:encode_mapping(Map)).

mapping_empty_test() ->
    ?assertEqual(<<0:16>>, i2p_router_info:encode_mapping(#{})),
    ?assertEqual({ok, #{}}, i2p_router_info:parse_mapping(<<0:16>>)).

mapping_sorted_test() ->
    Map = #{<<"z">> => <<"1">>, <<"a">> => <<"2">>, <<"m">> => <<"3">>},
    Pairs = <<
        1:8,
        <<"a">>/binary,
        $=,
        1:8,
        <<"2">>/binary,
        $;,
        1:8,
        <<"m">>/binary,
        $=,
        1:8,
        <<"3">>/binary,
        $;,
        1:8,
        <<"z">>/binary,
        $=,
        1:8,
        <<"1">>/binary,
        $;
    >>,
    ?assertEqual(<<(byte_size(Pairs)):16/big, Pairs/binary>>, i2p_router_info:encode_mapping(Map)).

mapping_rejects_garbage_test() ->
    ?assertEqual(error, i2p_router_info:parse_mapping(<<3:16, "abc">>)),
    ?assertEqual(error, i2p_router_info:parse_mapping(<<4:16, "a=b;">>)),
    ?assertEqual(error, i2p_router_info:parse_mapping(<<5:16, "a=b;x">>)).

%%% --------------------------------------------------------------------------
%%% Validation rejections
%%% --------------------------------------------------------------------------

null_timestamp_rejected_test() ->
    {Identity, Seed} = test_identity(),
    RI = i2p_router_info:build(Identity, 0, [ntcp2_addr()], router_options(), Seed),
    ?assertEqual({error, {bad_timestamp, 0}}, i2p_router_info:parse(i2p_router_info:to_binary(RI))).

netid_mismatch_rejected_test() ->
    {Identity, Seed} = test_identity(),
    Opts = maps:put(<<"netId">>, <<"1">>, router_options()),
    RI = i2p_router_info:build(Identity, 1_800_000_000, [ntcp2_addr()], Opts, Seed),
    ?assertEqual({error, net_id_mismatch}, i2p_router_info:parse(i2p_router_info:to_binary(RI))).

missing_router_version_rejected_test() ->
    {Identity, Seed} = test_identity(),
    Opts = maps:remove(<<"router.version">>, router_options()),
    RI = i2p_router_info:build(Identity, 1_800_000_000, [ntcp2_addr()], Opts, Seed),
    ?assertEqual(
        {error, missing_router_version}, i2p_router_info:parse(i2p_router_info:to_binary(RI))
    ).

nonpublished_ntcp2_accepted_but_not_dialable_test() ->
    {Identity, Seed} = test_identity(),
    %% Unreachable NTCP2 address: caps only, no host/port/IV.
    Addr = #{
        transport => <<"NTCP2">>,
        cost => 14,
        expiration => 0,
        options => #{
            <<"caps">> => <<"4">>,
            <<"s">> => i2p_keys:encode_b64(static_key()),
            <<"v">> => <<"2">>
        }
    },
    RI = i2p_router_info:build(Identity, 1_800_000_000, [Addr], router_options(), Seed),
    {ok, Parsed} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    ?assertEqual({error, no_reachable_ntcp2}, i2p_router_info:ntcp2_connector(Parsed)).

malformed_inputs_rejected_test() ->
    ?assertEqual({error, too_short}, i2p_router_info:parse(<<>>)),
    ?assertEqual({error, too_short}, i2p_router_info:parse(<<0:32>>)),
    ?assertEqual({error, badarg}, i2p_router_info:parse(not_a_binary)).

%%% --------------------------------------------------------------------------
%%% m3p2 block (msg3 payload)
%%% --------------------------------------------------------------------------

m3p2_block_layout_test() ->
    {Identity, Seed} = test_identity(),
    RI = build(Identity, Seed, [ntcp2_addr()]),
    Bin = i2p_router_info:to_binary(RI),
    Block = i2p_router_info:m3p2_block(RI),
    ?assertEqual(<<2:8, (byte_size(Bin) + 1):16/big, 0:8, Bin/binary>>, Block),
    %% The block must decode back as a type-2 RouterInfo block.
    {ok, [Block2]} = i2p_framing:decode_blocks(Block),
    #{type := 2, data := <<0:8, Bin2/binary>>} = Block2,
    ?assertEqual(Bin, Bin2).

%%% --------------------------------------------------------------------------
%%% ntcp2_connector
%%% --------------------------------------------------------------------------

connector_extracts_connect_info_test() ->
    {Identity, Seed} = test_identity(),
    RI = build(Identity, Seed, [ntcp2_addr()]),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, Conn} = i2p_router_info:ntcp2_connector(RI),
    ?assertEqual(<<"192.0.2.10">>, maps:get(host, Conn)),
    ?assertEqual(4668, maps:get(port, Conn)),
    ?assertEqual(static_key(), maps:get(static, Conn)),
    ?assertEqual(iv(), maps:get(iv, Conn)).

connector_skips_non_ntcp2_and_unreachable_test() ->
    {Identity, Seed} = test_identity(),
    SSU2 = #{
        transport => <<"SSU2">>,
        cost => 5,
        expiration => 0,
        options => #{<<"host">> => <<"192.0.2.20">>, <<"port">> => <<"4669">>}
    },
    Unreachable = #{
        transport => <<"NTCP2">>,
        cost => 14,
        expiration => 0,
        options => #{
            <<"caps">> => <<"4">>, <<"s">> => i2p_keys:encode_b64(static_key()), <<"v">> => <<"2">>
        }
    },
    RI = i2p_router_info:build(
        Identity, 1_800_000_000, [SSU2, Unreachable, ntcp2_addr()], router_options(), Seed
    ),
    {ok, RI} = i2p_router_info:parse(i2p_router_info:to_binary(RI)),
    {ok, #{host := <<"192.0.2.10">>}} = i2p_router_info:ntcp2_connector(RI).

connector_no_ntcp2_test() ->
    {Identity, Seed} = test_identity(),
    RI = i2p_router_info:build(Identity, 1_800_000_000, [], router_options(), Seed),
    ?assertEqual({error, no_reachable_ntcp2}, i2p_router_info:ntcp2_connector(RI)).

%%% --------------------------------------------------------------------------
%%% Router-level caps composition and validation
%%% --------------------------------------------------------------------------

caps_string_composes_valid_forms_test() ->
    ?assertEqual(<<"RL">>, i2p_router_info:caps_string($L, true, false)),
    ?assertEqual(<<"UL">>, i2p_router_info:caps_string($L, false, false)),
    ?assertEqual(<<"RLf">>, i2p_router_info:caps_string($L, true, true)),
    ?assertEqual(<<"UMf">>, i2p_router_info:caps_string($M, false, true)),
    ?assertEqual(<<"RX">>, i2p_router_info:caps_string($X, true, false)).

caps_string_rejects_bad_bandwidth_test() ->
    ?assertError({bad_caps_bandwidth, $_}, i2p_router_info:caps_string($_, true, false)),
    ?assertError({bad_caps_bandwidth, $l}, i2p_router_info:caps_string($l, true, false)).

validate_caps_accepts_valid_test() ->
    ?assert(i2p_router_info:validate_caps(<<"L">>)),
    ?assert(i2p_router_info:validate_caps(<<"RL">>)),
    ?assert(i2p_router_info:validate_caps(<<"RLf">>)),
    ?assert(i2p_router_info:validate_caps(<<"UL">>)),
    ?assert(i2p_router_info:validate_caps(<<"X">>)),
    ?assert(i2p_router_info:validate_caps(<<"fL">>)).

validate_caps_rejects_malformed_test() ->
    ?assertNot(i2p_router_info:validate_caps(<<>>)),
    %% A lone floodfill marker with no bandwidth class is invalid.
    ?assertNot(i2p_router_info:validate_caps(<<"f">>)),
    %% At most one reachability flag, no duplicates, no unknown letters.
    ?assertNot(i2p_router_info:validate_caps(<<"RU">>)),
    ?assertNot(i2p_router_info:validate_caps(<<"RR">>)),
    ?assertNot(i2p_router_info:validate_caps(<<"UU">>)),
    ?assertNot(i2p_router_info:validate_caps(<<"ff">>)),
    ?assertNot(i2p_router_info:validate_caps(<<"Z">>)),
    ?assertNot(i2p_router_info:validate_caps(12)).

validate_caps_rejects_repeated_bandwidth_classes_test() ->
    ?assertNot(i2p_router_info:validate_caps(<<"LL">>)),
    ?assertNot(i2p_router_info:validate_caps(<<"KL">>)),
    ?assertNot(i2p_router_info:validate_caps(<<"RLfM">>)).

%%% --------------------------------------------------------------------------
%%% Helpers
%%% --------------------------------------------------------------------------

build(Identity, Seed, Addresses) ->
    i2p_router_info:build(Identity, 1_800_000_000, Addresses, router_options(), Seed).

test_identity() ->
    {CPub, _} = i2p_crypto:x25519_keygen(),
    {SPub, Seed} = i2p_crypto:ed25519_keygen(),
    {i2p_keys:from_keys(CPub, SPub), Seed}.

router_options() ->
    #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>}.

ntcp2_addr() ->
    i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()).

static_key() ->
    <<16#0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A:256>>.

iv() ->
    <<16#0B0BB0B00B0BB0B00B0BB0B00B0BB0B0:128>>.

intro_key() ->
    <<16#0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C:256>>.

%% Three distinct introducer entries (hash, tag, optional expiry) for the
%% indexed ih/itag/iexp publishing tests.
test_introducers() ->
    [
        #{hash => hash2(), tag => 7, exp => 900},
        #{hash => hash3(), tag => 16#01020304, exp => 1_800_001_000},
        #{hash => hash4(), tag => 16#FFFFFFFF}
    ].

hash2() ->
    <<16#1111111111111111111111111111111111111111111111111111111111111111:256>>.

hash3() ->
    <<16#2222222222222222222222222222222222222222222222222222222222222222:256>>.

hash4() ->
    <<16#3333333333333333333333333333333333333333333333333333333333333333:256>>.

%% Extract the mapping bytes that follow the address header.
mapping_of(Bin) ->
    <<_Cost:8, _Exp:64/big, StyleLen:8, _Style:StyleLen/binary, Mapping/binary>> = Bin,
    Mapping.

flip_byte(Bin, Index) ->
    <<Pre:Index/binary, B:8, Post/binary>> = Bin,
    <<Pre/binary, (B bxor 16#FF):8, Post/binary>>.
