-module(i2p_framing_prop_tests).

%% Property tests for the NTCP2 data-phase framing layer.
%%
%% Invariants under test:
%%   - obfuscate_length/2 : deobfuscate_length/2 round-trips every valid
%%     length and chains the SipHash state identically on both sides
%%   - the length mask is a pure function of the SipHash state: two lengths
%%     masked against the same state cancel under XOR
%%   - deobfuscate_length/2 never returns an out-of-range length, and its
%%     recovery is the centre-inverse of obfuscate_length/2
%%   - encrypt_frame/4 : decrypt_frame/4 round-trips any payload and message
%%     number, advancing the SipHash state identically on both sides
%%   - data_phase_keys/2 derives distinct, correctly-sized per-direction keys
%%   - encode_block/2 : decode_blocks/1 are inverse over whole block lists

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%% --------------------------------------------------------------------------
%%% Length obfuscation
%%% --------------------------------------------------------------------------

length_roundtrip_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, Length},
                {sip_state_gen(), integer(16, 65535)},
                begin
                    {Obf, Sip1} = i2p_framing:obfuscate_length(Length, Sip),
                    {ok, Length, Sip1} =:= i2p_framing:deobfuscate_length(Obf, Sip)
                end
            ),
            [{numtests, 200}]
        )
    ).

mask_is_state_function_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, L1, L2},
                {sip_state_gen(), integer(16, 65535), integer(16, 65535)},
                begin
                    {O1, _Sip1} = i2p_framing:obfuscate_length(L1, Sip),
                    {O2, _Sip2} = i2p_framing:obfuscate_length(L2, Sip),
                    O1 bxor L1 =:= O2 bxor L2
                end
            ),
            [{numtests, 200}]
        )
    ).

deobfuscate_centre_inverse_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Sip, ObfLen},
                {sip_state_gen(), integer(0, 65535)},
                case i2p_framing:deobfuscate_length(ObfLen, Sip) of
                    {ok, Length, Sip1} ->
                        Length >= 16 andalso
                            Length =< 65535 andalso
                            {ObfLen, Sip1} =:= i2p_framing:obfuscate_length(Length, Sip);
                    error ->
                        true
                end
            ),
            [{numtests, 200}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Frame round-trips
%%% --------------------------------------------------------------------------

frame_roundtrip_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Key, Sip, MsgNum, Payload},
                {binary(32), sip_state_gen(), integer(0, 65535), payload_gen()},
                begin
                    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, MsgNum, Payload, Sip),
                    byte_size(Frame) =:= 18 + byte_size(Payload) andalso
                        case i2p_framing:decrypt_frame(Key, MsgNum, Frame, Sip) of
                            {ok, Payload, Sip1} -> true;
                            _ -> false
                        end
                end
            ),
            [{numtests, 100}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Key derivation
%%% --------------------------------------------------------------------------

data_phase_keys_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                {Ck, H},
                {binary(32), binary(32)},
                begin
                    #{k_ab := KAb, k_ba := KBa, sip_ab := SipAb, sip_ba := SipBa} =
                        i2p_framing:data_phase_keys(Ck, H),
                    KAb =/= KBa andalso
                        byte_size(KAb) =:= 32 andalso
                        byte_size(KBa) =:= 32 andalso
                        SipAb =/= SipBa andalso
                        byte_size(maps:get(key, SipAb)) =:= 16 andalso
                        byte_size(maps:get(iv, SipAb)) =:= 8 andalso
                        byte_size(maps:get(key, SipBa)) =:= 16 andalso
                        byte_size(maps:get(iv, SipBa)) =:= 8
                end
            ),
            [{numtests, 100}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Blocks
%%% --------------------------------------------------------------------------

blocks_roundtrip_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                Blocks,
                list(block_gen()),
                begin
                    Encoded = iolist_to_binary([
                        i2p_framing:encode_block(Type, Data)
                     || #{type := Type, data := Data} <- Blocks
                    ]),
                    {ok, Blocks} =:= i2p_framing:decode_blocks(Encoded)
                end
            ),
            [{numtests, 100}]
        )
    ).

%%% --------------------------------------------------------------------------
%%% Generators
%%% --------------------------------------------------------------------------

sip_state_gen() ->
    ?LET(
        {Key, IV},
        {binary(16), binary(8)},
        #{key => Key, iv => IV}
    ).

payload_gen() ->
    ?LET(Size, integer(0, 65519), binary(Size)).

block_gen() ->
    ?LET(
        {Type, Data},
        {integer(0, 255), ?LET(Size, integer(0, 64), binary(Size))},
        #{type => Type, data => Data}
    ).
