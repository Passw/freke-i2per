%% NTCP2 data-phase stream reassembler. A TCP byte stream has no
%% message boundaries, so i2p_stream must cut frames from arbitrary byte splits:
%% a frame may arrive whole, split across reads, or several in one read.

-module(i2p_stream_tests).

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% Round-trips across delivery shapes
%% --------------------------------------------------------------------------

whole_frame_test() ->
    {Key, Sip, Frame, Payload} = make_frame(<<"hello bob">>),
    S0 = i2p_stream:new(Key, Sip),
    {ok, S1, [Payload]} = i2p_stream:push(S0, Frame),
    ?assertEqual(0, i2p_stream:size(S1)).

byte_at_a_time_test() ->
    {Key, Sip, Frame, Payload} = make_frame(<<"hello bob">>),
    S0 = i2p_stream:new(Key, Sip),
    {ok, S1, []} = i2p_stream:push(S0, <<>>),
    {ok, S2, [Payload]} = push_bytes(Frame, S1, []),
    ?assertEqual(0, i2p_stream:size(S2)).

push_bytes(<<>>, Stream, Acc) ->
    {ok, Stream, lists:reverse(Acc)};
push_bytes(<<B:8, Rest/binary>>, Stream, Acc) ->
    {ok, Stream1, Payloads} = i2p_stream:push(Stream, <<B:8>>),
    push_bytes(Rest, Stream1, Payloads ++ Acc).

three_frames_one_push_test() ->
    {Key, Sip0, _, _} = make_frame(<<"unused">>),
    %% Three consecutive frames on the same key/sip chain.
    {F1, Sip1} = i2p_framing:encrypt_frame(Key, 0, <<"one">>, Sip0),
    {F2, Sip2} = i2p_framing:encrypt_frame(Key, 1, <<"two">>, Sip1),
    {F3, _Sip3} = i2p_framing:encrypt_frame(Key, 2, <<"three">>, Sip2),
    S0 = i2p_stream:new(Key, Sip0),
    All = <<F1/binary, F2/binary, F3/binary>>,
    {ok, S1, [P1, P2, P3]} = i2p_stream:push(S0, All),
    ?assertEqual([<<"one">>, <<"two">>, <<"three">>], [P1, P2, P3]),
    ?assertEqual(0, i2p_stream:size(S1)).

half_then_half_test() ->
    {Key, Sip, Frame, Payload} = make_frame(<<"split me">>),
    Len = byte_size(Frame),
    Half = Len div 2,
    <<Head:Half/binary, Tail/binary>> = Frame,
    S0 = i2p_stream:new(Key, Sip),
    {ok, S1, []} = i2p_stream:push(S0, Head),
    ?assertEqual(Half, i2p_stream:size(S1)),
    {ok, S2, [Payload]} = i2p_stream:push(S1, Tail),
    ?assertEqual(0, i2p_stream:size(S2)).

frame_spans_two_reads_with_partial_next_test() ->
    {Key, Sip0, F1, P1} = make_frame(<<"first">>),
    {F2, _} = i2p_framing:encrypt_frame(Key, 1, <<"second">>, sip1_after(F1, Sip0)),
    Both = <<F1/binary, F2/binary>>,
    Cut = byte_size(F1) + 1,
    <<Head:Cut/binary, Tail/binary>> = Both,
    S0 = i2p_stream:new(Key, Sip0),
    {ok, S1, [P1]} = i2p_stream:push(S0, Head),
    {ok, S2, [<<"second">>]} = i2p_stream:push(S1, Tail),
    ?assertEqual(0, i2p_stream:size(S2)).

%% The SipHash state after encrypting F1 (the IV advances to each frame's
%% output), so the next frame is encrypted on the chained state.
sip1_after(F1, Sip0) ->
    <<ObfLen:16/big, _/binary>> = F1,
    {ok, _Len, Sip1} = i2p_framing:deobfuscate_length(ObfLen, Sip0),
    Sip1.

%% --------------------------------------------------------------------------
%% Rejection
%% --------------------------------------------------------------------------

tamper_rejected_test() ->
    {Key, Sip, Frame, _} = make_frame(<<"secret">>),
    S0 = i2p_stream:new(Key, Sip),
    %% flip one byte inside the sealed frame -> MAC failure
    Flip = flip_byte(Frame, 4),
    ?assertEqual(error, i2p_stream:push(S0, Flip)),
    %% corrupt the obfuscated length so it deobfuscates out of range
    S1 = i2p_stream:new(Key, Sip),
    <<ObfLen:16/big, Sealed/binary>> = Frame,
    ?assertEqual(error, i2p_stream:push(S1, <<(ObfLen bxor 16):16/big, Sealed/binary>>)).

%% --------------------------------------------------------------------------
%% Helpers
%% --------------------------------------------------------------------------

make_frame(Payload) ->
    Keys = i2p_framing:data_phase_keys(
        crypto:strong_rand_bytes(32),
        crypto:strong_rand_bytes(32)
    ),
    #{k_ab := Key, sip_ab := Sip} = Keys,
    {Frame, _} = i2p_framing:encrypt_frame(Key, 0, Payload, Sip),
    {Key, Sip, Frame, Payload}.

flip_byte(Bin, Index) ->
    <<Pre:Index/binary, B:8, Post/binary>> = Bin,
    <<Pre/binary, (B bxor 16#FF):8, Post/binary>>.
