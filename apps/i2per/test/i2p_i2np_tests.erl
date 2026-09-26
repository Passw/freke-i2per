-module(i2p_i2np_tests).

%% Unit tests for the I2NP message layer.
%%
%% Coverage:
%%   - encode/1 / decode/1: short-header wire layout (byte-level KAT),
%%     truncated-header rejection
%%   - db_store/5 + decode_db_store/1: RouterInfo and LeaseSet store types,
%%     reply-token variants, truncated bodies
%%   - db_lookup/4 + decode_db_lookup/1: lookup-type flags, delivery flag,
%%     excluded peers, overlong exclusion rejection
%%   - db_search_reply/3 + decode_db_search_reply/1: round-trip, peer cap
%%   - delivery_status/2 + decode_delivery_status/1: round-trip
%%   - gzip_router_info/1: exact I2P gzip header bytes, round-trip against a
%%     signed RouterInfo, i2pd's stored-block (GzipNoCompression) variant
%%   - router_info_data/1 + parse_router_info_data/1: round-trip

-include_lib("eunit/include/eunit.hrl").

-define(GZIP_HEADER, <<16#1F, 16#8B, 8, 0, 0:32/big, 2, 16#FF>>).

%%% --------------------------------------------------------------------------
%%% Short header
%%% --------------------------------------------------------------------------

short_header_wire_layout_test() ->
    Msg = #{
        type => 1,
        msg_id => <<16#01020304:32/big>>,
        expiration => 16#05060708,
        body => <<"x">>
    },
    %% type(1) ‖ msg_id(4) ‖ short_exp(4) ‖ body
    ?assertEqual(
        <<1, 16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08, "x">>,
        i2p_i2np:encode(Msg)
    ).

short_header_roundtrip_test() ->
    Msg = #{
        type => 3,
        msg_id => <<0, 0, 0, 42>>,
        expiration => 1_800_000_000,
        body => crypto:strong_rand_bytes(100)
    },
    ?assertEqual({ok, Msg}, i2p_i2np:decode(i2p_i2np:encode(Msg))).

short_header_truncated_test() ->
    %% 8 bytes is one short of the 9-byte header.
    ?assertEqual(error, i2p_i2np:decode(<<1, 0, 0, 0, 0, 0, 0, 0>>)),
    ?assertEqual(error, i2p_i2np:decode(<<>>)).

msg_type_constants_test() ->
    ?assertEqual(1, i2p_i2np:type_database_store()),
    ?assertEqual(2, i2p_i2np:type_database_lookup()),
    ?assertEqual(3, i2p_i2np:type_database_search_reply()),
    ?assertEqual(10, i2p_i2np:type_delivery_status()),
    ?assertEqual(11, i2p_i2np:type_garlic()),
    ?assertEqual(18, i2p_i2np:type_tunnel_data()),
    ?assertEqual(19, i2p_i2np:type_tunnel_gateway()),
    ?assertEqual(25, i2p_i2np:type_short_tunnel_build()),
    ?assertEqual(26, i2p_i2np:type_outbound_tunnel_build_reply()),
    ?assertEqual(0, i2p_i2np:store_type_router_info()),
    ?assertEqual(1, i2p_i2np:store_type_leaseset()),
    ?assertEqual(0, i2p_i2np:lookup_type_any()),
    ?assertEqual(4, i2p_i2np:lookup_type_leaseset()),
    ?assertEqual(8, i2p_i2np:lookup_type_routerinfo()),
    ?assertEqual(12, i2p_i2np:lookup_type_exploratory()).

%%% --------------------------------------------------------------------------
%%% DatabaseStore
%%% --------------------------------------------------------------------------

db_store_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    Data = <<1, 2, 3, 4>>,
    Msg = i2p_i2np:db_store(Key, 0, 0, undefined, Data),
    ?assertEqual(i2p_i2np:type_database_store(), maps:get(type, Msg)),
    ?assertEqual(4, byte_size(maps:get(msg_id, Msg))),
    Body = maps:get(body, Msg),
    %% key(32) ‖ type(1) ‖ reply token(4) ‖ data
    ?assertEqual(<<Key/binary, 0, 0:32/big, Data/binary>>, Body),
    {ok, Decoded} = i2p_i2np:decode_db_store(Body),
    ?assertEqual(Key, maps:get(key, Decoded)),
    ?assertEqual(0, maps:get(store_type, Decoded)),
    ?assertEqual(0, maps:get(reply_token, Decoded)),
    ?assertEqual(undefined, maps:get(reply, Decoded)),
    ?assertEqual(Data, maps:get(data, Decoded)).

db_store_reply_token_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    Gateway = crypto:strong_rand_bytes(32),
    Data = crypto:strong_rand_bytes(64),
    Msg = i2p_i2np:db_store(Key, 0, 1234, {5678, Gateway}, Data),
    Body = maps:get(body, Msg),
    %% key(32) ‖ type(1) ‖ token(4) ‖ tunnel(4) ‖ gateway(32) ‖ data
    ?assertEqual(
        <<Key/binary, 0, 1234:32/big, 5678:32/big, Gateway/binary, Data/binary>>,
        Body
    ),
    {ok, Decoded} = i2p_i2np:decode_db_store(Body),
    ?assertEqual(1234, maps:get(reply_token, Decoded)),
    ?assertEqual({5678, Gateway}, maps:get(reply, Decoded)),
    ?assertEqual(Data, maps:get(data, Decoded)).

db_store_reply_token_requires_target_test() ->
    ?assertError(badarg, i2p_i2np:db_store(crypto:strong_rand_bytes(32), 0, 5, undefined, <<1>>)),
    ?assertError(
        badarg,
        i2p_i2np:db_store(crypto:strong_rand_bytes(32), 0, 5, {1, <<0>>}, <<1>>)
    ).

db_store_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_db_store(<<0:256>>)),
    %% A nonzero reply token needs the 36 reply bytes.
    ?assertEqual(
        error,
        i2p_i2np:decode_db_store(<<0:256, 0, 5:32/big, 1, 2, 3>>)
    ).

db_store_leaseset_type_test() ->
    Key = crypto:strong_rand_bytes(32),
    LS = crypto:strong_rand_bytes(300),
    Msg = i2p_i2np:db_store(Key, 1, 0, undefined, LS),
    Body = maps:get(body, Msg),
    {ok, Decoded} = i2p_i2np:decode_db_store(Body),
    ?assertEqual(1, maps:get(store_type, Decoded)),
    ?assertEqual(LS, maps:get(data, Decoded)).

%%% --------------------------------------------------------------------------
%%% DatabaseLookup
%%% --------------------------------------------------------------------------

db_lookup_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    Excluded = [crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(32)],
    Msg = i2p_i2np:db_lookup(Key, From, i2p_i2np:lookup_type_exploratory(), Excluded),
    ?assertEqual(i2p_i2np:type_database_lookup(), maps:get(type, Msg)),
    Body = maps:get(body, Msg),
    {ok, Decoded} = i2p_i2np:decode_db_lookup(Body),
    ?assertEqual(Key, maps:get(key, Decoded)),
    ?assertEqual(From, maps:get(from, Decoded)),
    ?assertEqual(exploratory, maps:get(type, Decoded)),
    ?assertEqual(false, maps:get(encrypted, Decoded)),
    ?assertEqual(undefined, maps:get(delivery, Decoded)),
    ?assertEqual(Excluded, maps:get(excluded, Decoded)),
    ?assertEqual(<<>>, maps:get(reply_encryption, Decoded)).

db_lookup_wire_layout_test() ->
    Key = <<16#AA:256>>,
    From = <<16#BB:256>>,
    %% flags byte is the exploratory lookup type (0x0C), delivery flag clear.
    Body = i2p_i2np:encode(i2p_i2np:db_lookup(Key, From, 12, [])),
    ?assertMatch(
        <<_Type:8, _MsgID:32/big, _Exp:32/big, 16#AA:256, 16#BB:256, 16#0C, 0:16/big>>,
        Body
    ).

db_lookup_types_test() ->
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    lists:foreach(
        fun({Type, Name}) ->
            Body = maps:get(body, i2p_i2np:db_lookup(Key, From, Type, [])),
            {ok, Decoded} = i2p_i2np:decode_db_lookup(Body),
            ?assertEqual(Name, maps:get(type, Decoded))
        end,
        [
            {0, any},
            {4, leaseset},
            {8, routerinfo},
            {12, exploratory}
        ]
    ).

db_lookup_delivery_flag_test() ->
    %% Hand-built body with the delivery flag set: key(32) from(32) flags
    %% (0x01 | 0x08) tunnel(4) size(2) excluded.
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    Peer = crypto:strong_rand_bytes(32),
    Body = <<Key/binary, From/binary, (1 bor 8), 777:32/big, 1:16/big, Peer/binary>>,
    {ok, Decoded} = i2p_i2np:decode_db_lookup(Body),
    ?assertEqual(routerinfo, maps:get(type, Decoded)),
    ?assertEqual(#{tunnel_id => 777}, maps:get(delivery, Decoded)),
    ?assertEqual([Peer], maps:get(excluded, Decoded)).

db_lookup_overlong_excluded_test() ->
    %% 513 excluded peers (max 512) — must fail to parse, not OOM.
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    Peers = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 513)],
    Body = <<Key/binary, From/binary, 8, (length(Peers)):16/big, (iolist_to_binary(Peers))/binary>>,
    ?assertEqual(error, i2p_i2np:decode_db_lookup(Body)).

db_lookup_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_db_lookup(<<0:256>>)),
    %% Delivery flag set but the tunnel ID is truncated.
    ?assertEqual(
        error,
        i2p_i2np:decode_db_lookup(<<0:256, 1:8, 1, 2, 3>>)
    ).

%%% --------------------------------------------------------------------------
%%% DatabaseSearchReply
%%% --------------------------------------------------------------------------

db_search_reply_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    Peers = [
        crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(32)
    ],
    From = crypto:strong_rand_bytes(32),
    Msg = i2p_i2np:db_search_reply(Key, Peers, From),
    Body = maps:get(body, Msg),
    %% key(32) ‖ num(1) ‖ peers(num*32) ‖ from(32)
    ?assertEqual(<<Key/binary, 3, (iolist_to_binary(Peers))/binary, From/binary>>, Body),
    {ok, Decoded} = i2p_i2np:decode_db_search_reply(Body),
    ?assertEqual(Key, maps:get(key, Decoded)),
    ?assertEqual(Peers, maps:get(peers, Decoded)),
    ?assertEqual(From, maps:get(from, Decoded)).

db_search_reply_empty_test() ->
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    Msg = i2p_i2np:db_search_reply(Key, [], From),
    {ok, Decoded} = i2p_i2np:decode_db_search_reply(maps:get(body, Msg)),
    ?assertEqual([], maps:get(peers, Decoded)).

db_search_reply_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_db_search_reply(<<0:256>>)),
    Key = crypto:strong_rand_bytes(32),
    %% num says 2 but only one hash present.
    ?assertEqual(
        error,
        i2p_i2np:decode_db_search_reply(<<Key/binary, 2, 0:256>>)
    ).

%%% --------------------------------------------------------------------------
%%% DeliveryStatus
%%% --------------------------------------------------------------------------

delivery_status_roundtrip_test() ->
    MsgID = <<1, 2, 3, 4>>,
    TimeMs = 1_800_000_000_000,
    Msg = i2p_i2np:delivery_status(MsgID, TimeMs),
    ?assertEqual(i2p_i2np:type_delivery_status(), maps:get(type, Msg)),
    ?assertEqual(<<MsgID/binary, TimeMs:64/big>>, maps:get(body, Msg)),
    ?assertEqual({ok, MsgID, TimeMs}, i2p_i2np:decode_delivery_status(maps:get(body, Msg))).

delivery_status_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_delivery_status(<<1, 2, 3>>)).

%%% --------------------------------------------------------------------------
%%% RouterInfo gzip
%%% --------------------------------------------------------------------------

gzip_router_info_header_test() ->
    Gzip = i2p_i2np:gzip_router_info(crypto:strong_rand_bytes(100)),
    <<Header:10/binary, _/binary>> = Gzip,
    %% mtime 0, XFL 2, OS 0xFF — exactly 1F 8B 08 00 00 00 00 00 02 FF.
    ?assertEqual(<<16#1F, 16#8B, 8, 0, 0:32/big, 2, 16#FF>>, Header).

gzip_router_info_roundtrip_test() ->
    RI = sample_router_info(),
    Bin = i2p_router_info:to_binary(RI),
    Gzip = i2p_i2np:gzip_router_info(Bin),
    ?assertEqual({ok, Bin}, i2p_i2np:gunzip_router_info(Gzip)),
    %% Compresses a signed RouterInfo.
    ?assert(byte_size(Gzip) < byte_size(Bin)).

gzip_stored_block_i2pd_variant_test() ->
    %% i2pd's GzipNoCompression emits a gzip frame with a *stored* deflate
    %% block: header(11) ‖ LEN(2 LE) ‖ ~LEN(2 LE) ‖ data ‖ crc(4 LE) ‖ isize(4 LE).
    Data = crypto:strong_rand_bytes(500),
    Len = byte_size(Data),
    Stored =
        <<16#1F, 16#8B, 8, 0, 0:32/big, 2, 16#FF, 16#01, Len:16/little, (16#FFFF - Len):16/little,
            Data/binary, (erlang:crc32(Data)):32/little, Len:32/little>>,
    ?assertEqual({ok, Data}, i2p_i2np:gunzip_router_info(Stored)).

gunzip_invalid_test() ->
    ?assertEqual(error, i2p_i2np:gunzip_router_info(<<16#1F, 16#8B, 8, 0, 0, 1, 2, 3>>)),
    ?assertEqual(error, i2p_i2np:gunzip_router_info(<<"not gzip">>)).

router_info_data_roundtrip_test() ->
    RI = sample_router_info(),
    Bin = i2p_router_info:to_binary(RI),
    Data = i2p_i2np:router_info_data(Bin),
    ?assertEqual({ok, Bin}, i2p_i2np:parse_router_info_data(Data)).

router_info_data_truncated_test() ->
    ?assertEqual(error, i2p_i2np:parse_router_info_data(<<10, 20>>)),
    %% size claims more bytes than present.
    ?assertEqual(error, i2p_i2np:parse_router_info_data(<<100:16/big, "short">>)).

db_store_router_info_end_to_end_test() ->
    %% A full DatabaseStore for a signed RouterInfo, parsed back.
    RI = sample_router_info(),
    Bin = i2p_router_info:to_binary(RI),
    Key = i2p_router_info:hash(RI),
    Msg = i2p_i2np:db_store(Key, 0, 0, undefined, i2p_i2np:router_info_data(Bin)),
    Wire = i2p_i2np:encode(Msg),
    {ok, #{body := Body}} = i2p_i2np:decode(Wire),
    {ok, #{key := Key, store_type := 0, data := Data}} = i2p_i2np:decode_db_store(Body),
    ?assertEqual({ok, Bin}, i2p_i2np:parse_router_info_data(Data)),
    %% The recovered bytes still parse as a RouterInfo.
    {ok, _} = i2p_router_info:parse(Bin).

%%% --------------------------------------------------------------------------
%%% Standard 16-byte header
%%% --------------------------------------------------------------------------

std_header_wire_layout_test() ->
    Body = <<"hello">>,
    <<Checksum:8, _/binary>> = crypto:hash(sha256, Body),
    Msg = #{
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration_ms => 1_800_000_000_000,
        body => Body
    },
    Wire = i2p_i2np:encode_std(Msg),
    %% type(1) msg_id(4) exp_ms(8) size(2) checksum(1) body
    ?assertEqual(
        <<11, 1, 2, 3, 4, 1_800_000_000_000:64/big, 5:16/big, Checksum, "hello">>,
        Wire
    ).

std_header_roundtrip_test() ->
    Msg = #{
        type => 19,
        msg_id => <<10, 20, 30, 40>>,
        expiration_ms => 999_999_999_999,
        body => crypto:strong_rand_bytes(200)
    },
    Wire = i2p_i2np:encode_std(Msg),
    {ok, Decoded} = i2p_i2np:decode_std(Wire),
    ?assertEqual(maps:get(type, Msg), maps:get(type, Decoded)),
    ?assertEqual(maps:get(msg_id, Msg), maps:get(msg_id, Decoded)),
    ?assertEqual(maps:get(expiration_ms, Msg), maps:get(expiration_ms, Decoded)),
    ?assertEqual(maps:get(body, Msg), maps:get(body, Decoded)).

std_header_empty_body_test() ->
    Msg = #{type => 18, msg_id => <<0, 0, 0, 1>>, expiration_ms => 0, body => <<>>},
    {ok, Decoded} = i2p_i2np:decode_std(i2p_i2np:encode_std(Msg)),
    ?assertEqual(maps:get(type, Msg), maps:get(type, Decoded)),
    ?assertEqual(maps:get(msg_id, Msg), maps:get(msg_id, Decoded)),
    ?assertEqual(maps:get(expiration_ms, Msg), maps:get(expiration_ms, Decoded)),
    ?assertEqual(maps:get(body, Msg), maps:get(body, Decoded)).

std_header_checksum_zero_tolerated_test() ->
    Msg = #{type => 11, msg_id => <<1, 2, 3, 4>>, expiration_ms => 100, body => <<"x">>},
    Wire = i2p_i2np:encode_std(Msg),
    %% Overwrite the checksum byte with 0.
    <<Pre:16/binary, _Old:8, Rest/binary>> = Wire,
    Tampered = <<Pre/binary, 0, Rest/binary>>,
    ?assertMatch({ok, _}, i2p_i2np:decode_std(Tampered)).

std_header_size_mismatch_test() ->
    Msg = #{type => 11, msg_id => <<1, 2, 3, 4>>, expiration_ms => 100, body => <<"abc">>},
    Wire = i2p_i2np:encode_std(Msg),
    <<Pre:13/binary, _OldSize:16/big, Rest/binary>> = Wire,
    Tampered = <<Pre/binary, 999:16/big, Rest/binary>>,
    ?assertEqual(error, i2p_i2np:decode_std(Tampered)).

std_header_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_std(<<1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)),
    ?assertEqual(error, i2p_i2np:decode_std(<<>>)).

%%% --------------------------------------------------------------------------
%%% Garlic (type 11)
%%% --------------------------------------------------------------------------

garlic_roundtrip_test() ->
    Data = crypto:strong_rand_bytes(500),
    Msg = i2p_i2np:garlic(Data),
    ?assertEqual(i2p_i2np:type_garlic(), maps:get(type, Msg)),
    {ok, Decoded} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    ?assertEqual(byte_size(Data), maps:get(length, Decoded)),
    ?assertEqual(Data, maps:get(data, Decoded)).

garlic_wire_layout_test() ->
    Data = <<"garlic payload">>,
    Msg = i2p_i2np:garlic(Data),
    ?assertEqual(<<14:32/big, "garlic payload">>, maps:get(body, Msg)).

garlic_empty_data_test() ->
    Msg = i2p_i2np:garlic(<<>>),
    ?assertEqual(<<0:32/big>>, maps:get(body, Msg)),
    ?assertEqual(
        {ok, #{length => 0, data => <<>>}},
        i2p_i2np:decode_garlic(maps:get(body, Msg))
    ).

garlic_max_size_test() ->
    MaxData = crypto:strong_rand_bytes(65536),
    Msg = i2p_i2np:garlic(MaxData),
    {ok, Decoded} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    ?assertEqual(65536, maps:get(length, Decoded)),
    ?assertEqual(MaxData, maps:get(data, Decoded)).

garlic_too_large_test() ->
    ?assertError(badarg, i2p_i2np:garlic(crypto:strong_rand_bytes(65537))).

garlic_length_mismatch_test() ->
    ?assertEqual(error, i2p_i2np:decode_garlic(<<99:32/big, "short">>)).

garlic_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_garlic(<<0, 0, 0>>)).

%%% --------------------------------------------------------------------------
%%% TunnelData (type 18)
%%% --------------------------------------------------------------------------

tunnel_data_roundtrip_test() ->
    TunnelID = 42,
    IV = crypto:strong_rand_bytes(16),
    Encrypted = crypto:strong_rand_bytes(1008),
    TunnelMsg = <<TunnelID:32/big, IV/binary, Encrypted/binary>>,
    Msg = i2p_i2np:tunnel_data(TunnelMsg),
    ?assertEqual(i2p_i2np:type_tunnel_data(), maps:get(type, Msg)),
    ?assertEqual(TunnelMsg, maps:get(body, Msg)),
    {ok, Decoded} = i2p_i2np:decode_tunnel_data(TunnelMsg),
    ?assertEqual(TunnelID, maps:get(tunnel_id, Decoded)),
    ?assertEqual(IV, maps:get(iv, Decoded)),
    ?assertEqual(Encrypted, maps:get(encrypted, Decoded)).

tunnel_data_wire_layout_test() ->
    TunnelID = 16#DEADBEEF,
    IV = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>,
    Encrypted = crypto:strong_rand_bytes(1008),
    Msg = i2p_i2np:tunnel_data(<<TunnelID:32/big, IV/binary, Encrypted/binary>>),
    ?assertEqual(<<TunnelID:32/big, IV/binary, Encrypted/binary>>, maps:get(body, Msg)).

tunnel_data_wrong_size_test() ->
    ?assertError(badarg, i2p_i2np:tunnel_data(<<0:800>>)),
    ?assertError(badarg, i2p_i2np:tunnel_data(crypto:strong_rand_bytes(1029))),
    ?assertError(badarg, i2p_i2np:tunnel_data(<<>>)).

tunnel_data_decode_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_tunnel_data(<<0:100>>)).

%%% --------------------------------------------------------------------------
%%% TunnelGateway (type 19)
%%% --------------------------------------------------------------------------

tunnel_gateway_roundtrip_test() ->
    InnerBody = crypto:strong_rand_bytes(100),
    StdMsg = i2p_i2np:encode_std(#{
        type => 11,
        msg_id => <<5, 6, 7, 8>>,
        expiration_ms => 2_000_000_000_000,
        body => InnerBody
    }),
    Msg = i2p_i2np:tunnel_gateway(777, StdMsg),
    ?assertEqual(i2p_i2np:type_tunnel_gateway(), maps:get(type, Msg)),
    {ok, Decoded} = i2p_i2np:decode_tunnel_gateway(maps:get(body, Msg)),
    ?assertEqual(777, maps:get(tunnel_id, Decoded)),
    ?assertEqual(StdMsg, maps:get(body, Decoded)),
    #{msg := InnerMsg} = Decoded,
    ?assertEqual(11, maps:get(type, InnerMsg)),
    ?assertEqual(InnerBody, maps:get(body, InnerMsg)).

tunnel_gateway_wire_layout_test() ->
    InnerBody = <<42:32, 43:32>>,
    StdMsg = i2p_i2np:encode_std(#{
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration_ms => 500,
        body => InnerBody
    }),
    Msg = i2p_i2np:tunnel_gateway(99, StdMsg),
    Body = maps:get(body, Msg),
    Size = byte_size(StdMsg),
    ?assertEqual(<<99:32/big, Size:16/big, StdMsg/binary>>, Body).

tunnel_gateway_size_mismatch_test() ->
    StdMsg = i2p_i2np:encode_std(#{
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration_ms => 500,
        body => <<>>
    }),
    Msg = i2p_i2np:tunnel_gateway(1, StdMsg),
    Body = maps:get(body, Msg),
    <<TunnelID:32/big, _OldSize:16/big, Rest/binary>> = Body,
    Tampered = <<TunnelID:32/big, 9999:16/big, Rest/binary>>,
    ?assertEqual(error, i2p_i2np:decode_tunnel_gateway(Tampered)).

tunnel_gateway_truncated_test() ->
    ?assertEqual(error, i2p_i2np:decode_tunnel_gateway(<<0:10>>)).

%%% --------------------------------------------------------------------------
%%% ShortTunnelBuild (type 25)
%%% --------------------------------------------------------------------------

short_tunnel_build_roundtrip_test() ->
    Records = [crypto:strong_rand_bytes(218) || _ <- lists:seq(1, 4)],
    Msg = i2p_i2np:short_tunnel_build(Records),
    ?assertEqual(i2p_i2np:type_short_tunnel_build(), maps:get(type, Msg)),
    {ok, Decoded} = i2p_i2np:decode_short_tunnel_build(maps:get(body, Msg)),
    ?assertEqual(4, maps:get(num, Decoded)),
    ?assertEqual(Records, maps:get(records, Decoded)).

short_tunnel_build_wire_layout_test() ->
    R1 = crypto:strong_rand_bytes(218),
    R2 = crypto:strong_rand_bytes(218),
    Msg = i2p_i2np:short_tunnel_build([R1, R2]),
    Body = maps:get(body, Msg),
    ?assertEqual(<<2:8, R1/binary, R2/binary>>, Body).

short_tunnel_build_single_record_test() ->
    Record = crypto:strong_rand_bytes(218),
    Msg = i2p_i2np:short_tunnel_build([Record]),
    ?assertEqual(<<1:8, Record/binary>>, maps:get(body, Msg)),
    {ok, Decoded} = i2p_i2np:decode_short_tunnel_build(maps:get(body, Msg)),
    ?assertEqual(1, maps:get(num, Decoded)),
    ?assertEqual([Record], maps:get(records, Decoded)).

short_tunnel_build_max_records_test() ->
    Records = [crypto:strong_rand_bytes(218) || _ <- lists:seq(1, 8)],
    Msg = i2p_i2np:short_tunnel_build(Records),
    {ok, Decoded} = i2p_i2np:decode_short_tunnel_build(maps:get(body, Msg)),
    ?assertEqual(8, maps:get(num, Decoded)),
    ?assertEqual(Records, maps:get(records, Decoded)).

short_tunnel_build_empty_rejected_test() ->
    ?assertError(badarg, i2p_i2np:short_tunnel_build([])).

short_tunnel_build_too_many_records_test() ->
    Records = [crypto:strong_rand_bytes(218) || _ <- lists:seq(1, 9)],
    ?assertError(badarg, i2p_i2np:short_tunnel_build(Records)).

short_tunnel_build_wrong_record_size_test() ->
    ?assertError(badarg, i2p_i2np:short_tunnel_build([crypto:strong_rand_bytes(217)])),
    ?assertError(badarg, i2p_i2np:short_tunnel_build([crypto:strong_rand_bytes(219)])).

short_tunnel_build_num_mismatch_test() ->
    %% Hand-build body with num=3 but only 2 records.
    R1 = crypto:strong_rand_bytes(218),
    R2 = crypto:strong_rand_bytes(218),
    ?assertEqual(error, i2p_i2np:decode_short_tunnel_build(<<3:8, R1/binary, R2/binary>>)).

short_tunnel_build_body_not_multiple_test() ->
    ?assertEqual(error, i2p_i2np:decode_short_tunnel_build(<<2:8, 0:300>>)).

%%% --------------------------------------------------------------------------
%%% OutboundTunnelBuildReply (type 26, OTBRM)
%%% --------------------------------------------------------------------------

otbrm_roundtrip_test() ->
    Records = [crypto:strong_rand_bytes(218) || _ <- lists:seq(1, 3)],
    Msg = i2p_i2np:outbound_tunnel_build_reply(Records),
    ?assertEqual(i2p_i2np:type_outbound_tunnel_build_reply(), maps:get(type, Msg)),
    {ok, Decoded} = i2p_i2np:decode_outbound_tunnel_build_reply(maps:get(body, Msg)),
    ?assertEqual(3, maps:get(num, Decoded)),
    ?assertEqual(Records, maps:get(records, Decoded)).

otbrm_wire_layout_test() ->
    R1 = crypto:strong_rand_bytes(218),
    Msg = i2p_i2np:outbound_tunnel_build_reply([R1]),
    ?assertEqual(<<1:8, R1/binary>>, maps:get(body, Msg)).

otbrm_empty_rejected_test() ->
    ?assertError(badarg, i2p_i2np:outbound_tunnel_build_reply([])).

otbrm_wrong_record_size_test() ->
    ?assertError(badarg, i2p_i2np:outbound_tunnel_build_reply([crypto:strong_rand_bytes(100)])).

otbrm_num_mismatch_test() ->
    R1 = crypto:strong_rand_bytes(218),
    ?assertEqual(error, i2p_i2np:decode_outbound_tunnel_build_reply(<<5:8, R1/binary>>)).

%%% --------------------------------------------------------------------------
%%% Helpers
%%% --------------------------------------------------------------------------

sample_router_info() ->
    {CPub, _} = i2p_crypto:x25519_keygen(),
    {SPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(CPub, SPub),
    Addr = i2p_router_info:ntcp2_address(<<"192.0.2.10">>, 4668, static_key(), iv()),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, 1_800_000_000, [Addr], Opts, Seed).

static_key() ->
    <<16#0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A:256>>.

iv() ->
    <<16#0B0BB0B00B0BB0B00B0BB0B00B0BB0B0:128>>.
