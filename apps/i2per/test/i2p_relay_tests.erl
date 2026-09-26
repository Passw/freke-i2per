%% Unit tests for the SSU2 relay core: prologue literals, signed-data
%% construction, Ed25519 sign/verify per role, codec block building, reject-code
%% classification, and the nonce-derived out-of-session connection IDs.

-module(i2p_relay_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RELAY_REQUEST_PROLOGUE, <<"RelayRequestData">>).
-define(RELAY_RESPONSE_PROLOGUE, <<"RelayAgreementOK">>).

bob_hash() -> crypto:strong_rand_bytes(32).
charlie_hash() -> crypto:strong_rand_bytes(32).
ipv4() -> <<192, 0, 2, 10>>.
ipv6() -> <<16#2001:16, 16#0DB8:16, 0:16, 0:16, 0:16, 0:16, 16#ABCD:16, 16#EF01:16>>.
keys() -> i2p_crypto:ed25519_keygen().

prologue_literals_test() ->
    ?assertEqual(?RELAY_REQUEST_PROLOGUE, i2p_relay:prologue_request()),
    ?assertEqual(?RELAY_RESPONSE_PROLOGUE, i2p_relay:prologue_response()),
    ?assertEqual(16, byte_size(i2p_relay:prologue_request())),
    ?assertEqual(16, byte_size(i2p_relay:prologue_response())).

relay_request_signed_data_layout_test() ->
    Bob = bob_hash(),
    Charlie = charlie_hash(),
    Nonce = 16#AABBCCDD,
    Tag = 16#11223344,
    Ts = 1_700_000_000,
    Port = 49657,
    Ip = ipv4(),
    Data = i2p_relay:signed_data_request(Bob, Charlie, Nonce, Tag, Ts, 2, Port, Ip),
    ?assertEqual(16 + 32 + 32 + 4 + 4 + 4 + 1 + 1 + 2 + 4, byte_size(Data)),
    <<Prologue:16/binary, BobH:32/binary, CharlieH:32/binary, Nonce2:32, Tag2:32, Ts2:32, Ver:8,
        Asz:8, Port2:16, Ip2:4/binary>> = Data,
    ?assertEqual(?RELAY_REQUEST_PROLOGUE, Prologue),
    ?assertEqual(Bob, BobH),
    ?assertEqual(Charlie, CharlieH),
    ?assertEqual(Nonce, Nonce2),
    ?assertEqual(Tag, Tag2),
    ?assertEqual(Ts, Ts2),
    ?assertEqual(2, Ver),
    ?assertEqual(6, Asz),
    ?assertEqual(Port, Port2),
    ?assertEqual(Ip, Ip2).

relay_request_signed_data_ipv6_layout_test() ->
    Bob = bob_hash(),
    Charlie = charlie_hash(),
    Data = i2p_relay:signed_data_request(Bob, Charlie, 1, 2, 3, 2, 1234, ipv6()),
    ?assertEqual(16 + 32 + 32 + 4 + 4 + 4 + 1 + 1 + 2 + 16, byte_size(Data)),
    <<Prologue:16/binary, _BobH:32/binary, _CharlieH:32/binary, _Nonce:32, _Tag:32, _Ts:32, _Ver:8,
        Asz:8, Port:16, Ip:16/binary>> = Data,
    ?assertEqual(?RELAY_REQUEST_PROLOGUE, Prologue),
    ?assertEqual(18, Asz),
    ?assertEqual(1234, Port),
    ?assertEqual(ipv6(), Ip).

relay_response_signed_data_layout_test() ->
    Bob = bob_hash(),
    Nonce = 16#AABBCCDD,
    Ts = 1_700_000_000,
    Port = 49657,
    Ip = ipv4(),
    Data = i2p_relay:signed_data_response(Bob, Nonce, Ts, 2, Port, Ip),
    ?assertEqual(16 + 32 + 4 + 4 + 1 + 1 + 2 + 4, byte_size(Data)),
    <<Prologue:16/binary, BobH:32/binary, Nonce2:32, Ts2:32, Ver:8, Csz:8, Port2:16, Ip2:4/binary>> =
        Data,
    ?assertEqual(?RELAY_RESPONSE_PROLOGUE, Prologue),
    ?assertEqual(Bob, BobH),
    ?assertEqual(Nonce, Nonce2),
    ?assertEqual(Ts, Ts2),
    ?assertEqual(2, Ver),
    ?assertEqual(6, Csz),
    ?assertEqual(Port, Port2),
    ?assertEqual(Ip, Ip2).

%% A reject signed data has csz 0 and no endpoint bytes.
relay_response_signed_data_empty_endpoint_test() ->
    Bob = bob_hash(),
    Data = i2p_relay:signed_data_response(Bob, 1, 2, 2, 0, <<>>),
    ?assertEqual(16 + 32 + 4 + 4 + 1 + 1, byte_size(Data)),
    <<Prologue:16/binary, BobH:32/binary, _Nonce:32, _Ts:32, _Ver:8, 0:8>> = Data,
    ?assertEqual(?RELAY_RESPONSE_PROLOGUE, Prologue),
    ?assertEqual(Bob, BobH).

request_sign_verify_roundtrip_test() ->
    {Pub, Seed} = keys(),
    Bob = bob_hash(),
    Charlie = charlie_hash(),
    Sig = i2p_relay:sign_request(
        Bob,
        Charlie,
        2,
        16#AABBCCDD,
        16#11223344,
        1_700_000_000,
        49657,
        ipv4(),
        Seed
    ),
    ?assertEqual(64, byte_size(Sig)),
    ?assert(
        i2p_relay:verify_request(
            Bob,
            Charlie,
            2,
            16#AABBCCDD,
            16#11223344,
            1_700_000_000,
            49657,
            ipv4(),
            Sig,
            Pub
        )
    ),
    %% wrong nonce fails.
    ?assertNot(
        i2p_relay:verify_request(
            Bob,
            Charlie,
            2,
            16#AABBCCDD,
            16#11223344,
            1_700_000_001,
            49657,
            ipv4(),
            Sig,
            Pub
        )
    ),
    %% wrong (or absent) Charlie hash fails — it is part of the signed data.
    ?assertNot(
        i2p_relay:verify_request(
            Bob,
            charlie_hash(),
            2,
            16#AABBCCDD,
            16#11223344,
            1_700_000_000,
            49657,
            ipv4(),
            Sig,
            Pub
        )
    ).

response_sign_verify_roundtrip_test() ->
    {Pub, Seed} = keys(),
    Bob = bob_hash(),
    Sig = i2p_relay:sign_response(Bob, 2, 16#AABBCCDD, 1_700_000_000, 49657, ipv4(), Seed),
    ?assert(64 =:= byte_size(Sig)),
    ?assert(
        i2p_relay:verify_response(Bob, 2, 16#AABBCCDD, 1_700_000_000, 49657, ipv4(), Sig, Pub)
    ),
    %% the empty-endpoint (csz 0) reject is signed and verifies too.
    EmptySig = i2p_relay:sign_response(Bob, 2, 16#AABBCCDD, 1_700_000_000, 0, <<>>, Seed),
    ?assert(
        i2p_relay:verify_response(Bob, 2, 16#AABBCCDD, 1_700_000_000, 0, <<>>, EmptySig, Pub)
    ),
    %% an endpoint on the signed data that was signed without one fails.
    ?assertNot(
        i2p_relay:verify_response(Bob, 2, 16#AABBCCDD, 1_700_000_000, 49657, ipv4(), EmptySig, Pub)
    ).

%% The relay signature is over the prologue + hashes and the signed data: a
%% signature made for a different introducer hash does not verify.
request_sign_bob_hash_binds_test() ->
    {Pub, Seed} = keys(),
    Bob = bob_hash(),
    Sig = i2p_relay:sign_request(Bob, charlie_hash(), 2, 1, 2, 3, 9150, ipv4(), Seed),
    ?assertNot(
        i2p_relay:verify_request(bob_hash(), charlie_hash(), 2, 1, 2, 3, 9150, ipv4(), Sig, Pub)
    ).

%% sign/verify and the codec block round-trip agree: a signed block survives
%% encode/decode exactly.
signed_blocks_codec_roundtrip_test() ->
    {_Pub, Seed} = keys(),
    Bob = bob_hash(),
    Charlie = charlie_hash(),
    ReqSig = i2p_relay:sign_request(
        Bob,
        Charlie,
        2,
        16#AABBCCDD,
        16#11223344,
        1_700_000_000,
        49657,
        ipv4(),
        Seed
    ),
    ReqBlock = i2p_relay:request_block(
        2,
        16#AABBCCDD,
        16#11223344,
        1_700_000_000,
        49657,
        ipv4(),
        ReqSig
    ),
    {ok, [ReqBlock]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([ReqBlock])),
    AliceHash = bob_hash(),
    IntroBlock = i2p_relay:intro_block(
        2,
        AliceHash,
        16#AABBCCDD,
        16#11223344,
        1_700_000_000,
        49657,
        ipv4(),
        ReqSig
    ),
    {ok, [IntroBlock]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([IntroBlock])),
    RespSig = i2p_relay:sign_response(Bob, 2, 16#AABBCCDD, 1_700_000_000, 49657, ipv4(), Seed),
    RespBlock = i2p_relay:response_block(
        0,
        2,
        16#AABBCCDD,
        1_700_000_000,
        49657,
        ipv4(),
        RespSig,
        42
    ),
    {ok, [RespBlock]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([RespBlock])),
    RejectBlock = i2p_relay:response_block(
        3,
        2,
        16#AABBCCDD,
        1_700_000_000,
        49657,
        ipv4(),
        RespSig,
        undefined
    ),
    {ok, [RejectBlock]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([RejectBlock])).

conn_ids_derived_from_nonce_test() ->
    Nonce = 16#12345678,
    Dst = i2p_relay:dst_conn_id(Nonce),
    ?assertEqual((16#12345678 bsl 32) bor 16#12345678, Dst),
    ?assertEqual(Dst, i2p_peertest:dst_conn_id(Nonce)),
    ?assertEqual(bnot Dst band 16#FFFFFFFFFFFFFFFF, i2p_relay:src_conn_id(Nonce)),
    %% same derivation as peer test (bitwise inverse of dst).
    ?assertEqual(16#FFFFFFFFFFFFFFFF bxor Dst, i2p_relay:src_conn_id(Nonce)).

address_size_test() ->
    ?assertEqual(0, i2p_relay:address_size(<<>>)),
    ?assertEqual(6, i2p_relay:address_size(<<1, 2, 3, 4>>)),
    ?assertEqual(18, i2p_relay:address_size(ipv6())).

reject_code_classification_test() ->
    %% Bob rejects 1-6.
    lists:foreach(
        fun(Code) -> ?assert(i2p_relay:is_bob_reject(Code)) end,
        [1, 2, 3, 4, 5, 6]
    ),
    %% Charlie rejects 64-70.
    lists:foreach(
        fun(Code) -> ?assert(i2p_relay:is_charlie_reject(Code)) end,
        [64, 65, 66, 67, 68, 69, 70]
    ),
    lists:foreach(
        fun({C, Bob, Charlie}) ->
            ?assertEqual(Bob, i2p_relay:is_bob_reject(C)),
            ?assertEqual(Charlie, i2p_relay:is_charlie_reject(C))
        end,
        [
            {0, false, false},
            {7, false, false},
            {63, false, false},
            {71, false, false},
            {127, false, false},
            {128, false, false}
        ]
    ),
    ?assert(i2p_relay:is_reject(1)),
    ?assert(i2p_relay:is_reject(64)),
    ?assert(i2p_relay:is_reject(128)),
    ?assertNot(i2p_relay:is_reject(0)).
