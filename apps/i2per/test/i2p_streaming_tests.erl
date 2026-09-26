%% Unit tests for the streaming protocol packet codec.
%%
%% Wire-layout KAT against the field order in the streaming spec / Java
%% Packet.java (sendStreamId ‖ receiveStreamId ‖ sequenceNum ‖ ackThrough ‖
%% nackCount ‖ NACKs ‖ resendDelay ‖ flags ‖ optionSize ‖ optionData ‖
%% payload), encode/decode round-trips, spec option ordering, the zeroed-
%% signature-space signing rule, SYN replay-prevention hash form and
%% rejection of truncated / inconsistent / unsupported packets.

-module(i2p_streaming_tests).

-include_lib("eunit/include/eunit.hrl").

%%% --------------------------------------------------------------------------
%%% Wire layout
%%% --------------------------------------------------------------------------

minimal_header_layout_test() ->
    %% Hand-computed bytes for a bare packet: the layout KAT.
    P = i2p_streaming:new(16#01020304, 16#05060708, 3, 4),
    Expected =
        <<16#01020304:32, 16#05060708:32, 3:32, 4:32,
            %% nackCount
            0:8,
            %% resendDelay
            0:8,
            %% flags
            0:16,
            %% optionSize
            0:16>>,
    ?assertEqual(22, byte_size(Expected)),
    ?assertEqual(Expected, i2p_streaming:encode(P)).

nacks_and_payload_layout_test() ->
    P0 = i2p_streaming:new(1, 2, 5, 4),
    P = P0#{
        nacks => [16#AABBCCDD, 7],
        resend_delay => 3,
        payload => <<"xy">>
    },
    Bin = i2p_streaming:encode(P),
    ?assertEqual(
        <<1:32, 2:32, 5:32, 4:32, 2:8, 16#AABBCCDD:32, 7:32, 3:8, 0:16, 0:16, "xy">>,
        Bin
    ).

flag_constants_match_spec_bits_test() ->
    ?assertEqual(16#0001, i2p_streaming:flag_synchronize()),
    ?assertEqual(16#0002, i2p_streaming:flag_close()),
    ?assertEqual(16#0004, i2p_streaming:flag_reset()),
    ?assertEqual(16#0008, i2p_streaming:flag_signature_included()),
    ?assertEqual(16#0010, i2p_streaming:flag_signature_requested()),
    ?assertEqual(16#0020, i2p_streaming:flag_from_included()),
    ?assertEqual(16#0040, i2p_streaming:flag_delay_requested()),
    ?assertEqual(16#0080, i2p_streaming:flag_max_packet_size_included()),
    ?assertEqual(16#0100, i2p_streaming:flag_profile_interactive()),
    ?assertEqual(16#0200, i2p_streaming:flag_echo()),
    ?assertEqual(16#0400, i2p_streaming:flag_no_ack()).

%%% --------------------------------------------------------------------------
%%% Round trips
%%% --------------------------------------------------------------------------

data_packet_round_trip_test() ->
    P = (i2p_streaming:new(16#11223344, 16#55667788, 9, 8))#{
        nacks => [1, 2, 3],
        resend_delay => 2,
        payload => crypto:strong_rand_bytes(1730)
    },
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:encode(P)),
    ?assertEqual(16#11223344, i2p_streaming:send_id(Pkt)),
    ?assertEqual(16#55667788, i2p_streaming:recv_id(Pkt)),
    ?assertEqual(9, i2p_streaming:seq_num(Pkt)),
    ?assertEqual(8, i2p_streaming:ack_through(Pkt)),
    ?assertEqual([1, 2, 3], i2p_streaming:nacks(Pkt)),
    ?assertEqual(2, i2p_streaming:resend_delay(Pkt)),
    ?assertEqual(1730, byte_size(i2p_streaming:payload(Pkt))),
    ?assertNot(i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize())),
    %% Canonical form re-encodes to the identical bytes.
    ?assertEqual(i2p_streaming:encode(P), i2p_streaming:encode(Pkt)).

max_nacks_round_trip_test() ->
    Nacks = lists:seq(0, 254),
    P = (i2p_streaming:new(1, 2, 0, 254))#{nacks => Nacks},
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:encode(P)),
    ?assertEqual(Nacks, i2p_streaming:nacks(Pkt)).

plain_ack_form_test() ->
    %% seqNum 0 without SYNCHRONIZE is a plain ACK; it decodes untouched.
    P = i2p_streaming:new(16#AAAA, 16#BBBB, 0, 42),
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:encode(P)),
    ?assertEqual(0, i2p_streaming:seq_num(Pkt)),
    ?assertEqual(42, i2p_streaming:ack_through(Pkt)),
    ?assertNot(i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize())).

unknown_flag_bits_preserved_test() ->
    %% Bits 12–15 are unused; a decoder must not reject them.
    Flags = 16#1000 bor i2p_streaming:flag_delay_requested(),
    P = (i2p_streaming:new(1, 2, 0, 0))#{flags => Flags, delay_ms => 10},
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:encode(P)),
    ?assertEqual(Flags, i2p_streaming:flags(Pkt)).

with_flags_preserves_existing_bits_test() ->
    P0 = i2p_streaming:with_flags(
        i2p_streaming:new(1, 2, 0, 0),
        i2p_streaming:flag_synchronize()
    ),
    P1 = i2p_streaming:with_flags(P0, i2p_streaming:flag_no_ack()),
    ?assertEqual(
        i2p_streaming:flag_synchronize() bor i2p_streaming:flag_no_ack(),
        i2p_streaming:flags(P1)
    ).

%%% --------------------------------------------------------------------------
%%% Options region
%%% --------------------------------------------------------------------------

option_order_is_delay_from_maxps_test() ->
    DestBin = fixture_dest(),
    P = i2p_streaming:with_flags(
        i2p_streaming:new(1, 2, 0, 0),
        i2p_streaming:flag_delay_requested() bor
            i2p_streaming:flag_from_included() bor
            i2p_streaming:flag_max_packet_size_included()
    ),
    Bin = i2p_streaming:encode(P#{
        delay_ms => 5,
        from => DestBin,
        max_packet_size => 1730
    }),
    %% nackCount+resendDelay+flags+optionSize = 6 bytes after the header ints;
    %% option data must appear in spec order delay ‖ from ‖ maxPacketSize.
    <<_:22/binary, 5:16, DestBin:391/binary, 1730:16>> = Bin.

syn_options_round_trip_test() ->
    {Pub, Seed} = i2p_crypto:ed25519_keygen(),
    DestBin = fixture_dest(),
    Hash = rand_hash(),
    P0 = i2p_streaming:with_flags(
        i2p_streaming:new(0, 16#CAFEBABE, 0, 0),
        i2p_streaming:flag_synchronize() bor
            i2p_streaming:flag_from_included() bor
            i2p_streaming:flag_max_packet_size_included() bor
            i2p_streaming:flag_no_ack()
    ),
    Syn = i2p_streaming:signed(
        P0#{
            from => DestBin,
            max_packet_size => 1730,
            nacks => i2p_streaming:syn_replay_nacks(Hash)
        },
        Seed
    ),
    {ok, Pkt} = i2p_streaming:decode(Syn),
    ?assert(i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize())),
    ?assert(i2p_streaming:has_flag(Pkt, i2p_streaming:flag_no_ack())),
    ?assertEqual(DestBin, i2p_streaming:from(Pkt)),
    ?assertEqual(1730, i2p_streaming:max_packet_size(Pkt)),
    ?assertEqual(undefined, i2p_streaming:delay_ms(Pkt)),
    ?assertEqual(64, byte_size(i2p_streaming:signature(Pkt))),
    ?assert(i2p_streaming:verify(Pkt, Pub)).

signature_covers_zeroed_space_test() ->
    %% Independent check of the signing rule: re-zero the signature region by
    %% hand and verify with the raw crypto API.
    {Pub, Seed} = i2p_crypto:ed25519_keygen(),
    P = i2p_streaming:with_flags(
        i2p_streaming:new(7, 8, 0, 0),
        i2p_streaming:flag_signature_included()
    ),
    Bin = i2p_streaming:signed(P#{payload => <<"abc">>}, Seed),
    {ok, Pkt} = i2p_streaming:decode(Bin),
    Off = maps:get(sig_offset, Pkt),
    Sig = i2p_streaming:signature(Pkt),
    <<Pre:Off/binary, _:64/binary, Post/binary>> = Bin,
    Zeroed = <<Pre/binary, 0:512, Post/binary>>,
    true = i2p_crypto:ed25519_verify(Zeroed, Sig, Pub),
    ?assert(i2p_streaming:verify(Pkt, Pub)).

verify_rejects_payload_tamper_test() ->
    {Pub, Seed} = i2p_crypto:ed25519_keygen(),
    P = i2p_streaming:with_flags(
        i2p_streaming:new(1, 2, 0, 0),
        i2p_streaming:flag_signature_included()
    ),
    Bin = i2p_streaming:signed(P#{payload => <<"attack at dawn">>}, Seed),
    Tampered = binary:replace(Bin, <<"dawn">>, <<"dusk">>),
    {ok, Pkt} = i2p_streaming:decode(Tampered),
    ?assertNot(i2p_streaming:verify(Pkt, Pub)).

verify_rejects_wrong_key_test() ->
    {PubGood, Seed} = i2p_crypto:ed25519_keygen(),
    {PubBad, _} = i2p_crypto:ed25519_keygen(),
    P = i2p_streaming:with_flags(
        i2p_streaming:new(1, 2, 0, 0),
        i2p_streaming:flag_signature_included()
    ),
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:signed(P, Seed)),
    ?assert(i2p_streaming:verify(Pkt, PubGood)),
    ?assertNot(i2p_streaming:verify(Pkt, PubBad)).

%%% --------------------------------------------------------------------------
%%% Replay prevention (SYN carrying the recipient's destination hash)
%%% --------------------------------------------------------------------------

replay_hash_round_trip_test() ->
    Hash = rand_hash(),
    Nacks = i2p_streaming:syn_replay_nacks(Hash),
    ?assertEqual(8, length(Nacks)),
    ?assertEqual(Hash, <<<<N:32>> || N <- Nacks>>),
    P = i2p_streaming:with_flags(
        i2p_streaming:new(0, 5, 0, 0),
        i2p_streaming:flag_synchronize()
    ),
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:encode(P#{nacks => Nacks})),
    ?assertEqual({ok, Hash}, i2p_streaming:replay_hash(Pkt)).

replay_hash_absent_on_plain_syn_test() ->
    P = i2p_streaming:with_flags(
        i2p_streaming:new(0, 5, 0, 0),
        i2p_streaming:flag_synchronize()
    ),
    {ok, Pkt} = i2p_streaming:decode(i2p_streaming:encode(P)),
    ?assertEqual(error, i2p_streaming:replay_hash(Pkt)).

%%% --------------------------------------------------------------------------
%%% Rejections
%%% --------------------------------------------------------------------------

truncated_header_error_test() ->
    ?assertEqual({error, truncated_header}, i2p_streaming:decode(<<>>)),
    Short21 =
        <<1:32, 2:32, 3:32, 4:32, 0:8, 0:8, 0:16, 0:8>>,
    ?assertEqual(21, byte_size(Short21)),
    ?assertEqual({error, truncated_header}, i2p_streaming:decode(Short21)),
    NackOverflow =
        <<1:32, 2:32, 3:32, 4:32, 200:8, 1:32, 0:8, 0:16, 0:16>>,
    ?assertEqual({error, truncated_header}, i2p_streaming:decode(NackOverflow)).

truncated_options_error_test() ->
    %% OptionSize claims 10 bytes but only 4 follow.
    Bin = <<1:32, 2:32, 3:32, 4:32, 0:8, 0:8, 0:16, 10:16, 1, 2, 3, 4>>,
    ?assertEqual({error, truncated_options}, i2p_streaming:decode(Bin)).

option_size_mismatch_error_test() ->
    %% No flagged options but a nonzero optionSize: leftover data is an error.
    Bin = <<1:32, 2:32, 3:32, 4:32, 0:8, 0:8, 0:16, 4:16, 1, 2, 3, 4>>,
    ?assertMatch(
        {error, {option_size_mismatch, 0, 4}},
        i2p_streaming:decode(Bin)
    ).

offline_signature_flag_rejected_test() ->
    Bin = <<1:32, 2:32, 3:32, 4:32, 0:8, 0:8, 16#0800:16, 4:16, 1, 2, 3, 4>>,
    ?assertEqual({error, malformed_options}, i2p_streaming:decode(Bin)).

malformed_option_length_error_test() ->
    %% DELAY_REQUESTED set but fewer than 2 bytes remain in the options region.
    Bin = <<1:32, 2:32, 3:32, 4:32, 0:8, 0:8, 16#0040:16, 1:16, 9>>,
    ?assertEqual({error, malformed_options}, i2p_streaming:decode(Bin)).

short_from_destination_error_test() ->
    Bin = <<1:32, 2:32, 3:32, 4:32, 0:8, 0:8, 16#0020:16, 100:16, 0:100/unit:8>>,
    ?assertEqual({error, malformed_options}, i2p_streaming:decode(Bin)).

not_binary_error_test() ->
    ?assertEqual({error, not_binary}, i2p_streaming:decode(list_to_atom("x"))).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

fixture_dest() ->
    i2p_keys:to_binary(i2p_keys:generate_identity()).

rand_hash() ->
    crypto:strong_rand_bytes(32).
