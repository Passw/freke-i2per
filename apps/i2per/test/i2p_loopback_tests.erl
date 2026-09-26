%% Integration test: two router identities on one node are wired through the
%% NTCP2 stack. RouterInfo feeds the handshake, both sides derive framing
%% keys, and both directions exchange framed blocks.
%%
%% The tests use real RouterInfos and prove the modules interoperate
%% end-to-end.

-module(i2p_loopback_tests).

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% Full handshake (connector wiring -> keys)
%% --------------------------------------------------------------------------

%% Alice connects to Bob using only what ntcp2_connector/1 and hash/1 extract
%% from Bob's published RouterInfo; both sides derive identical keys.
loopback_handshake_test() ->
    Alice = router(),
    Bob = router(),
    {KeysA, KeysB, _Payload} = handshake(Alice, Bob, 0, 0),
    ?assertEqual(KeysA, KeysB),
    #{k_ab := KAb, k_ba := KBa} = KeysA,
    ?assertEqual(32, byte_size(KAb)),
    ?assertEqual(32, byte_size(KBa)),
    ?assertNotEqual(KAb, KBa).

%% With padding on both msg1 and msg2 the same wiring still agrees.
loopback_handshake_with_padding_test() ->
    Alice = router(),
    Bob = router(),
    {KeysA, KeysB, _Payload} = handshake(Alice, Bob, 64, 37),
    ?assertEqual(KeysA, KeysB).

%% --------------------------------------------------------------------------
%% msg3 carries a real, verifiable RouterInfo
%% --------------------------------------------------------------------------

%% Bob decodes the msg3 payload and recovers Alice's signed RouterInfo exactly.
loopback_msg3_routerinfo_verified_test() ->
    Alice = router(),
    Bob = router(),
    #{ri := AliceRI} = Alice,
    {_KeysA, _KeysB, Payload} = handshake(Alice, Bob, 0, 0),
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    Type2 = [B || #{type := 2, data := <<0:8, _/binary>>} = B <- Blocks],
    ?assertMatch([#{type := 2}], Type2),
    [#{data := <<0:8, RIBin/binary>>}] = Type2,
    {ok, ReceivedRI} = i2p_router_info:parse(RIBin),
    ?assertEqual(i2p_router_info:to_binary(AliceRI), i2p_router_info:to_binary(ReceivedRI)),
    ?assertEqual(i2p_router_info:hash(AliceRI), i2p_router_info:hash(ReceivedRI)).

%% The handshake connects to Bob's *published* address info, so a RouterInfo
%% whose static key or IV disagrees with the responder's real keys must fail.
loopback_wrong_published_static_rejected_test() ->
    Alice = router(),
    Bob = router(),
    #{ri := BobRI} = Bob,
    {ok, #{static := _S, iv := Iv}} = i2p_router_info:ntcp2_connector(BobRI),
    BobHash = i2p_router_info:hash(BobRI),
    %% Alice inits against a *different* static key than Bob actually holds.
    {OtherPub, _} = i2p_crypto:x25519_keygen(),
    {AlicePriv, AlicePub} = alice_static(Alice),
    S0A = i2p_ntcp2:alice_init(OtherPub, BobHash, Iv, AlicePriv, AlicePub),
    {BobPriv, BobPub} = bob_static(Bob),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, BobHash, Iv),
    #{ri := AliceRI} = Alice,
    Payload = i2p_router_info:m3p2_block(AliceRI),
    Opts1 = #{padlen => 0, m3p2len => byte_size(Payload) + 16, ts => 1_700_000_000},
    {ok, Msg1, _S1A} = i2p_ntcp2:create_msg1(S0A, crypto:strong_rand_bytes(32), Opts1, <<>>),
    ?assertEqual(error, i2p_ntcp2:receive_msg1(S0B, Msg1)).

%% --------------------------------------------------------------------------
%% Data-phase frames round-trip in both directions
%% --------------------------------------------------------------------------

loopback_data_phase_frames_test() ->
    Alice = router(),
    Bob = router(),
    {KeysA, KeysB, _Payload} = handshake(Alice, Bob, 0, 0),
    ?assertEqual(KeysA, KeysB),
    #{k_ab := KAb, sip_ab := SipAb0} = KeysA,
    #{k_ba := KBa, sip_ba := SipBa0} = KeysB,
    %% Alice -> Bob: three frames (nonce + sip state advance together).
    Block = i2p_framing:encode_block(3, <<16#4, 16#34, 16#5a, 16#89>>),
    Pad = i2p_framing:pad_block(8),
    PayloadAB = <<Block/binary, Pad/binary>>,
    {F1, SipAb1} = i2p_framing:encrypt_frame(KAb, 0, <<"hello bob">>, SipAb0),
    {F2, SipAb2} = i2p_framing:encrypt_frame(KAb, 1, PayloadAB, SipAb1),
    {F3, _SipAb3} = i2p_framing:encrypt_frame(KAb, 2, <<>>, SipAb2),
    {ok, <<"hello bob">>, SipAb1} = i2p_framing:decrypt_frame(KAb, 0, F1, SipAb0),
    {ok, PayloadAB, SipAb2} = i2p_framing:decrypt_frame(KAb, 1, F2, SipAb1),
    {ok, <<>>, _} = i2p_framing:decrypt_frame(KAb, 2, F3, SipAb2),
    {ok, [I2np, PadBlock]} = i2p_framing:decode_blocks(PayloadAB),
    ?assertMatch(#{type := 3, data := <<16#4, 16#34, 16#5a, 16#89>>}, I2np),
    ?assertMatch(#{type := 254, data := _}, PadBlock),
    %% Bob -> Alice: three frames on the other direction key/sip.
    {G1, SipBa1} = i2p_framing:encrypt_frame(KBa, 0, <<"hi alice">>, SipBa0),
    {G2, _SipBa2} = i2p_framing:encrypt_frame(KBa, 1, <<"second">>, SipBa1),
    {ok, <<"hi alice">>, SipBa1} = i2p_framing:decrypt_frame(KBa, 0, G1, SipBa0),
    {ok, <<"second">>, _} = i2p_framing:decrypt_frame(KBa, 1, G2, SipBa1).

%% A flipped byte in any data-phase frame must be rejected at the far end.
loopback_data_phase_tamper_rejected_test() ->
    Alice = router(),
    Bob = router(),
    {KeysA, _KeysB, _Payload} = handshake(Alice, Bob, 0, 0),
    #{k_ab := KAb, sip_ab := SipAb} = KeysA,
    {F, _} = i2p_framing:encrypt_frame(KAb, 0, <<"secret">>, SipAb),
    Tampered = flip_byte(F, 3),
    ?assertEqual(error, i2p_framing:decrypt_frame(KAb, 0, Tampered, SipAb)),
    ?assertMatch(
        {ok, <<"secret">>, _},
        i2p_framing:decrypt_frame(KAb, 0, F, SipAb)
    ).

%% --------------------------------------------------------------------------
%% Helpers
%% --------------------------------------------------------------------------

%% A full router node: identity, NTCP2 static keypair, IV and a signed
%% RouterInfo that publishes them.
router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 4668, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, 1_800_000_000, [Addr], Opts, Seed),
    #{static_priv => StaticPriv, static_pub => StaticPub, iv => IV, ri => RI}.

alice_static(#{static_priv := Priv, static_pub := Pub}) ->
    {Priv, Pub}.

bob_static(#{static_priv := Priv, static_pub := Pub}) ->
    {Priv, Pub}.

%% Run the full handshake: Alice initiates to Bob's published RouterInfo,
%% Bob responds with his own keypair, msg3 carries Alice's RouterInfo block.
%% Returns the two data-phase key maps and the recovered msg3 payload.
handshake(Alice, Bob, PadLen1, PadLen2) ->
    #{ri := BobRI} = Bob,
    {ok, #{static := BobStatic, iv := BobIV}} = i2p_router_info:ntcp2_connector(BobRI),
    BobHash = i2p_router_info:hash(BobRI),
    {AlicePriv, AlicePub} = alice_static(Alice),
    S0A = i2p_ntcp2:alice_init(BobStatic, BobHash, BobIV, AlicePriv, AlicePub),
    {BobPriv, BobPub} = bob_static(Bob),
    S0B = i2p_ntcp2:bob_init(BobPriv, BobPub, BobHash, BobIV),
    #{ri := AliceRI} = Alice,
    Payload = i2p_router_info:m3p2_block(AliceRI),
    Pad1 = crypto:strong_rand_bytes(PadLen1),
    Opts1 = #{padlen => PadLen1, m3p2len => byte_size(Payload) + 16, ts => 1_700_000_000},
    {ok, Msg1, S1A} = i2p_ntcp2:create_msg1(S0A, crypto:strong_rand_bytes(32), Opts1, Pad1),
    {ok, #{padlen := PadLen1, m3p2len := M3P2Len}, S1B} =
        i2p_ntcp2:receive_msg1(S0B, Msg1),
    ?assertEqual(byte_size(Payload) + 16, M3P2Len),
    Pad2 = crypto:strong_rand_bytes(PadLen2),
    {ok, Msg2, S2B} = i2p_ntcp2:create_msg2(S1B, crypto:strong_rand_bytes(32), Pad2, 1_700_000_010),
    {ok, #{padlen := PadLen2}, S2A} = i2p_ntcp2:receive_msg2(S1A, Msg2),
    {ok, Msg3, S3A} = i2p_ntcp2:create_msg3(S2A, Payload),
    {ok, Payload, S3B} = i2p_ntcp2:receive_msg3(S2B, Msg3),
    {i2p_ntcp2:data_phase_keys(S3A), i2p_ntcp2:data_phase_keys(S3B), Payload}.

flip_byte(Bin, Index) ->
    <<Pre:Index/binary, B:8, Post/binary>> = Bin,
    <<Pre/binary, (B bxor 16#FF):8, Post/binary>>.
