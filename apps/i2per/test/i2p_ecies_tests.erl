-module(i2p_ecies_tests).

-include_lib("eunit/include/eunit.hrl").

%%%%%%%%% Truncated identity hash %%%%%%%%%

truncated_identity_hash_test() ->
    Hash = crypto:hash(sha256, <<"test-router-identity">>),
    Trunc = i2p_ecies:truncated_identity_hash(Hash),
    ?assertEqual(16, byte_size(Trunc)),
    ?assertEqual(<<16#4CFF162BD47294B1B6769A0186BF7635:128>>, Trunc).

%%%%%%%%% Encrypt / decrypt round-trip (single hop) %%%%%%%%%

encrypt_decrypt_roundtrip_test() ->
    {HopPub, HopPriv} = crypto:generate_key(ecdh, x25519),
    {_EphPub, EphPriv} = crypto:generate_key(ecdh, x25519),
    HopIdHash = crypto:hash(sha256, <<"hop-router-identity">>),
    Plaintext = crypto:strong_rand_bytes(154),
    InitState = i2p_crypto:noise_n_initialize(),
    {EncRecord, H2, Ck1} =
        i2p_ecies:encrypt_build_record(EphPriv, HopPub, HopIdHash, InitState, Plaintext),
    ?assertEqual(218, byte_size(EncRecord)),
    %% The record is addressed by the hop's truncated identity hash
    <<HopTrunc:16/binary, EphPubGot:32/binary, _/binary>> = EncRecord,
    ?assertEqual(<<16#5978C528A8223D914B9DC7F6F9911836:128>>, HopTrunc),
    ?assertEqual(i2p_crypto:x25519_public_key(EphPriv), EphPubGot),
    case i2p_ecies:decrypt_build_request_record(HopPriv, HopPub, EncRecord) of
        {ok, Got, Hd, Ckd} ->
            ?assertEqual(Plaintext, Got),
            ?assertEqual(H2, Hd),
            ?assertEqual(Ck1, Ckd);
        error ->
            ?assert(false)
    end.

encrypt_decrypt_wrong_key_test() ->
    {HopPub, _HopPriv} = crypto:generate_key(ecdh, x25519),
    {_OtherPub, OtherPriv} = crypto:generate_key(ecdh, x25519),
    {_EphPub, EphPriv} = crypto:generate_key(ecdh, x25519),
    HopIdHash = crypto:hash(sha256, <<"hop-router-identity">>),
    Plaintext = crypto:strong_rand_bytes(154),
    InitState = i2p_crypto:noise_n_initialize(),
    {EncRecord, _, _} =
        i2p_ecies:encrypt_build_record(EphPriv, HopPub, HopIdHash, InitState, Plaintext),
    ?assertEqual(error, i2p_ecies:decrypt_build_request_record(OtherPriv, HopPub, EncRecord)).

%%%%%%%%% Multi-hop independent sessions %%%%%%%%%

multi_hop_independent_sessions_test() ->
    NHops = 3,
    HopKeys = [crypto:generate_key(ecdh, x25519) || _ <- lists:seq(1, NHops)],
    EphKeys = [crypto:generate_key(ecdh, x25519) || _ <- lists:seq(1, NHops)],
    Plaintexts = [crypto:strong_rand_bytes(154) || _ <- lists:seq(1, NHops)],
    HopDescs = [
        #{
            eph_priv => EphPriv,
            hop_pub => HopPub,
            id_hash => crypto:hash(sha256, <<"hop-", (integer_to_binary(I))/binary>>)
        }
     || {I, {{HopPub, _HopPriv}, {_EphPub, EphPriv}}} <-
            lists:zip(lists:seq(1, NHops), lists:zip(HopKeys, EphKeys))
    ],
    ObepPos = NHops - 1,
    {Records, HopBuildKeys} =
        i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, ObepPos),
    ?assertEqual(NHops, length(Records)),
    ?assertEqual(NHops, length(HopBuildKeys)),
    lists:foreach(fun(R) -> ?assertEqual(218, byte_size(R)) end, Records),
    %% Every hop decrypts from its OWN fresh Noise state — no cross-record
    %% chaining — and derives the same reply key and Noise hash the creator
    %% retained for that position. The endpoint additionally gets an IV key
    %% from the "TunnelLayerIVKey" derivation.
    lists:foreach(
        fun(I) ->
            {HopPub, HopPriv} = lists:nth(I, HopKeys),
            Slot = I - 1,
            %% The creator concealed this record under every earlier hop's
            %% reply key; each earlier hop's forward layering cancels one
            %% concealment layer, so by the time the message reaches us our
            %% slot carries zero remaining layers.
            Received =
                lists:foldl(
                    fun(K, Acc) ->
                        #{reply_key := PrevReplyKey} = lists:nth(K + 1, HopBuildKeys),
                        i2p_ecies:decrypt_reply_layer(PrevReplyKey, Acc, Slot)
                    end,
                    lists:nth(I, Records),
                    lists:seq(0, I - 2)
                ),
            {ok, Got, H, Ck} =
                i2p_ecies:decrypt_build_request_record(HopPriv, HopPub, Received),
            ?assertEqual(lists:nth(I, Plaintexts), Got),
            Keys =
                case I - 1 =:= ObepPos of
                    true -> i2p_ecies:derive_obep_keys(Ck);
                    false -> i2p_ecies:derive_reply_layer_keys(Ck)
                end,
            #{reply_key := RK, layer_key := LK, iv_key := IVK} = Keys,
            #{reply_key := ERK, layer_key := ELK, iv_key := EIVK, noise_h := EH} =
                lists:nth(I, HopBuildKeys),
            ?assertEqual(RK, ERK),
            ?assertEqual(LK, ELK),
            ?assertEqual(IVK, EIVK),
            ?assertEqual(H, EH)
        end,
        lists:seq(1, NHops)
    ).

%% Locate a record by truncated identity hash prefix.

find_own_record_found_test() ->
    Hashes = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
    Records = [
        begin
            <<P:16/binary, _/binary>> = H,
            <<P/binary, (crypto:strong_rand_bytes(202))/binary>>
        end
     || H <- Hashes
    ],
    ?assertEqual({ok, 0}, i2p_ecies:find_own_record(lists:nth(1, Hashes), Records)),
    ?assertEqual({ok, 1}, i2p_ecies:find_own_record(lists:nth(2, Hashes), Records)),
    ?assertEqual({ok, 2}, i2p_ecies:find_own_record(lists:nth(3, Hashes), Records)).

find_own_record_missing_test() ->
    Records = [crypto:strong_rand_bytes(218) || _ <- lists:seq(1, 2)],
    ?assertEqual(error, i2p_ecies:find_own_record(crypto:strong_rand_bytes(32), Records)).

%%%%%%%%% Reply/layer KDF %%%%%%%%%

derive_reply_layer_keys_deterministic_test() ->
    Ck = crypto:strong_rand_bytes(32),
    K1 = i2p_ecies:derive_reply_layer_keys(Ck),
    K2 = i2p_ecies:derive_reply_layer_keys(Ck),
    ?assertEqual(K1, K2).

derive_reply_layer_keys_structure_test() ->
    Ck = crypto:strong_rand_bytes(32),
    Keys = i2p_ecies:derive_reply_layer_keys(Ck),
    ?assert(maps:is_key(reply_key, Keys)),
    ?assert(maps:is_key(layer_key, Keys)),
    ?assert(maps:is_key(iv_key, Keys)),
    ?assertEqual(32, byte_size(maps:get(reply_key, Keys))),
    ?assertEqual(32, byte_size(maps:get(layer_key, Keys))),
    ?assertEqual(32, byte_size(maps:get(iv_key, Keys))),
    ?assertNotEqual(maps:get(reply_key, Keys), maps:get(layer_key, Keys)),
    ?assertNotEqual(maps:get(reply_key, Keys), maps:get(iv_key, Keys)),
    ?assertNotEqual(maps:get(layer_key, Keys), maps:get(iv_key, Keys)).

derive_obep_keys_deterministic_test() ->
    Ck = crypto:strong_rand_bytes(32),
    K1 = i2p_ecies:derive_obep_keys(Ck),
    K2 = i2p_ecies:derive_obep_keys(Ck),
    ?assertEqual(K1, K2).

derive_obep_keys_differs_from_non_obep_test() ->
    Ck = crypto:strong_rand_bytes(32),
    NonObep = i2p_ecies:derive_reply_layer_keys(Ck),
    Obep = i2p_ecies:derive_obep_keys(Ck),
    ?assertNotEqual(maps:get(iv_key, NonObep), maps:get(iv_key, Obep)),
    ?assertEqual(maps:get(reply_key, NonObep), maps:get(reply_key, Obep)),
    ?assertEqual(maps:get(layer_key, NonObep), maps:get(layer_key, Obep)).

%%%%%%%%% OBEP reply round-trip %%%%%%%%%

obep_reply_encrypt_decrypt_test() ->
    ReplyKey = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    Plaintext = crypto:strong_rand_bytes(202),
    RecordPos = 3,
    Enc = i2p_ecies:encrypt_reply_record(ReplyKey, Plaintext, H, RecordPos),
    ?assertEqual(218, byte_size(Enc)),
    {ok, Got} = i2p_ecies:decrypt_reply_record(ReplyKey, Enc, H, RecordPos),
    ?assertEqual(Plaintext, Got).

obep_reply_wrong_key_test() ->
    ReplyKey = crypto:strong_rand_bytes(32),
    WrongKey = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    Plaintext = crypto:strong_rand_bytes(202),
    Enc = i2p_ecies:encrypt_reply_record(ReplyKey, Plaintext, H, 0),
    ?assertEqual(error, i2p_ecies:decrypt_reply_record(WrongKey, Enc, H, 0)).

obep_reply_wrong_position_test() ->
    ReplyKey = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    Plaintext = crypto:strong_rand_bytes(202),
    Enc = i2p_ecies:encrypt_reply_record(ReplyKey, Plaintext, H, 0),
    ?assertEqual(error, i2p_ecies:decrypt_reply_record(ReplyKey, Enc, H, 1)).

obep_reply_wrong_ad_test() ->
    ReplyKey = crypto:strong_rand_bytes(32),
    H = crypto:strong_rand_bytes(32),
    WrongH = crypto:strong_rand_bytes(32),
    Plaintext = crypto:strong_rand_bytes(202),
    Enc = i2p_ecies:encrypt_reply_record(ReplyKey, Plaintext, H, 0),
    ?assertEqual(error, i2p_ecies:decrypt_reply_record(ReplyKey, Enc, WrongH, 0)).

%%%%%%%%% Reply layer round-trip %%%%%%%%%

reply_layer_encrypt_decrypt_test() ->
    LayerKey = crypto:strong_rand_bytes(32),
    Plaintext = crypto:strong_rand_bytes(218),
    RecordPos = 2,
    Enc = i2p_ecies:encrypt_reply_layer(LayerKey, Plaintext, RecordPos),
    ?assertEqual(218, byte_size(Enc)),
    Got = i2p_ecies:decrypt_reply_layer(LayerKey, Enc, RecordPos),
    ?assertEqual(Plaintext, Got).

reply_layer_different_positions_test() ->
    LayerKey = crypto:strong_rand_bytes(32),
    Plaintext = crypto:strong_rand_bytes(218),
    Enc0 = i2p_ecies:encrypt_reply_layer(LayerKey, Plaintext, 0),
    Enc1 = i2p_ecies:encrypt_reply_layer(LayerKey, Plaintext, 1),
    ?assertNotEqual(Enc0, Enc1).

%%%%%%%%% OBEP + layer chain round-trip %%%%%%%%%

obep_and_layer_chain_test() ->
    Ck = crypto:strong_rand_bytes(32),
    ObepKeys = i2p_ecies:derive_obep_keys(Ck),
    NonObepKeys = i2p_ecies:derive_reply_layer_keys(Ck),
    H = crypto:strong_rand_bytes(32),
    PlaintextOBEP = crypto:strong_rand_bytes(202),
    Plaintext0 = crypto:strong_rand_bytes(218),
    Plaintext1 = crypto:strong_rand_bytes(218),
    EncOBEP = i2p_ecies:encrypt_reply_record(
        maps:get(reply_key, ObepKeys), PlaintextOBEP, H, 2
    ),
    Enc0 = i2p_ecies:encrypt_reply_layer(
        maps:get(layer_key, NonObepKeys), Plaintext0, 0
    ),
    Enc1 = i2p_ecies:encrypt_reply_layer(
        maps:get(layer_key, NonObepKeys), Plaintext1, 1
    ),
    {ok, GotOBEP} = i2p_ecies:decrypt_reply_record(
        maps:get(reply_key, ObepKeys), EncOBEP, H, 2
    ),
    ?assertEqual(PlaintextOBEP, GotOBEP),
    Got0 = i2p_ecies:decrypt_reply_layer(
        maps:get(layer_key, NonObepKeys), Enc0, 0
    ),
    ?assertEqual(Plaintext0, Got0),
    Got1 = i2p_ecies:decrypt_reply_layer(
        maps:get(layer_key, NonObepKeys), Enc1, 1
    ),
    ?assertEqual(Plaintext1, Got1).

%%%%%%%%% encrypt_build_records rejects mismatched lists %%%%%%%%%

encrypt_build_records_mismatched_lengths_test() ->
    HopDesc = #{
        eph_priv => <<0:256>>,
        hop_pub => <<0:256>>,
        id_hash => <<0:256>>
    },
    ?assertError(
        function_clause,
        i2p_ecies:encrypt_build_records([HopDesc], [<<0:154>>, <<0:154>>], 0)
    ).

%%%%%%%%% encrypt_build_record rejects wrong plaintext size %%%%%%%%%

encrypt_build_record_wrong_size_test() ->
    {HopPub, _HopPriv} = crypto:generate_key(ecdh, x25519),
    {_EphPub, EphPriv} = crypto:generate_key(ecdh, x25519),
    InitState = i2p_crypto:noise_n_initialize(),
    ?assertError(
        function_clause,
        i2p_ecies:encrypt_build_record(
            EphPriv, HopPub, crypto:strong_rand_bytes(32), InitState, <<0:153>>
        )
    ).

%%%%%%%%% Creator/hop RGarlic key agreement %%%%%%%%%

%%
%% The OBEP derives its RGarlic wrap material from the chaining key of ITS
%% Noise N processing of the build record; the creator derives it from the
%% encryption-side chain. Both must agree, or delivered OTBRMs cannot be
%% unwrapped by the tunnel creator.
%%

obep_rgarlic_keys_agree_test() ->
    {HPub, HPriv} = i2p_crypto:x25519_keygen(),
    IdHash = crypto:strong_rand_bytes(32),
    {EPhPub, EphPriv} = i2p_crypto:x25519_keygen(),
    _ = EPhPub,
    Init = i2p_crypto:noise_n_initialize(),
    Plaintext = crypto:strong_rand_bytes(154),
    {EncRecord, _HCreator, CkCreator} =
        i2p_ecies:encrypt_build_record(EphPriv, HPub, IdHash, Init, Plaintext),
    %% Hop side: decrypting yields the identical chaining key
    {ok, Plaintext, _HHop, CkHop} =
        i2p_ecies:decrypt_build_request_record(HPriv, HPub, EncRecord),
    ?assertEqual(CkCreator, CkHop),
    %% Both sides derive the same RGarlic wrap material
    #{rgarlic_key := K1, rgarlic_tag := T1} = i2p_ecies:derive_obep_keys(CkCreator),
    #{rgarlic_key := K2, rgarlic_tag := T2} = i2p_ecies:derive_obep_keys(CkHop),
    ?assertEqual(K1, K2),
    ?assertEqual(T1, T2).
