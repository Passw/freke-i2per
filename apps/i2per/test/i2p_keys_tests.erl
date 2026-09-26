-module(i2p_keys_tests).

%% Known-answer and structural tests for the identity layer.
%%
%% Sources for the KATs:
%%   - Identity wire layout: reference i2p-java / i2pd (KeysAndCert,
%%     Proposal 161 padding compression; 384-byte keys region + certificate)
%%   - Base64: I2P alphabet `A-Za-z0-9-~`, `=` padding; a 391-byte identity
%%     encodes to 524 chars
%%   - Base32: RFC 4648 section 10 test vectors (lower-case, no padding)
%%   - Fixed identity constants: cross-verified with an independent Python
%%     reference (base64 with the I2P alphabet, hashlib.sha256, base32) over
%%     the same wire bytes; the Erlang module reproduces them exactly

-include_lib("eunit/include/eunit.hrl").

hx(Hex) -> binary:decode_hex(Hex).

cpub() ->
    hx(<<"33951964003c940878063ccfd0348af42150ca16d2646f2c5856e8338377d880">>).

spub() ->
    hx(<<"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a">>).

zero_padding() ->
    binary:copy(<<0>>, 320).

key_cert() ->
    <<5, 0, 4, 0, 7, 0, 4>>.

%%% --------------------------------------------------------------------------
%%% Structure and round-trips
%%% --------------------------------------------------------------------------

standard_identity_structure_test() ->
    Id = i2p_keys:generate_identity(),
    ?assertEqual(391, byte_size(i2p_keys:to_binary(Id))),
    ?assertEqual(32, byte_size(i2p_keys:hash(Id))),
    ?assertEqual(32, byte_size(i2p_keys:public_key(Id))),
    ?assertEqual(32, byte_size(i2p_keys:signing_key(Id))),
    ?assertEqual(320, byte_size(i2p_keys:padding(Id))),
    ?assertEqual(7, byte_size(i2p_keys:cert(Id))),
    ?assertEqual(5, i2p_keys:cert_type(Id)),
    ?assertEqual(7, i2p_keys:sig_type(Id)),
    ?assertEqual(4, i2p_keys:crypt_type(Id)),
    ?assertEqual(524, byte_size(i2p_keys:to_b64(Id))),
    ?assertEqual(60, byte_size(i2p_keys:to_b32(Id))),
    ?assertEqual(key_cert(), i2p_keys:cert(Id)).

generate_identity_roundtrip_test() ->
    Id = i2p_keys:generate_identity(),
    ?assertEqual({ok, Id}, i2p_keys:parse(i2p_keys:to_binary(Id))),
    ?assertEqual({ok, Id}, i2p_keys:from_b64(i2p_keys:to_b64(Id))),
    Id2 = i2p_keys:generate_identity(),
    ?assertNotEqual(i2p_keys:to_b64(Id), i2p_keys:to_b64(Id2)).

from_keys_test() ->
    Id = i2p_keys:from_keys(cpub(), spub()),
    ?assertEqual(cpub(), i2p_keys:public_key(Id)),
    ?assertEqual(spub(), i2p_keys:signing_key(Id)),
    %% wire layout: CPub at offset 0, SPub right-justified in the 384-byte
    %% keys region, KEY(5) certificate appended
    ?assertEqual(391, byte_size(i2p_keys:to_binary(Id))),
    Bin = i2p_keys:to_binary(Id),
    <<Pub:32/binary, _Pad:320/binary, SPub:32/binary, Cert/binary>> = Bin,
    ?assertEqual(cpub(), Pub),
    ?assertEqual(spub(), SPub),
    ?assertEqual(key_cert(), Cert),
    ?assertEqual({ok, Id}, i2p_keys:parse(Bin)),
    %% random padding per call: two identities with the same keys differ
    ?assertNotEqual(
        i2p_keys:to_b64(Id),
        i2p_keys:to_b64(i2p_keys:from_keys(cpub(), spub()))
    ).

%%% --------------------------------------------------------------------------
%%% Fixed identity KATs (independent Python verification)
%%% --------------------------------------------------------------------------

fixed_identity_kat_test() ->
    %% cpub() ++ 320 zero bytes ++ spub() ++ KEY(5) cert
    {ok, Id} = i2p_keys:parse(<<
        (cpub())/binary, (zero_padding())/binary, (spub())/binary, (key_cert())/binary
    >>),
    Hash = i2p_keys:hash(Id),
    ?assertEqual(
        hx(<<"e6a817ace83a9aa78bca7ea0aef0f681de3ece3d00bc7d2913cc5b7e0f7f91c5">>),
        Hash
    ),
    ?assertEqual(
        <<
            "M5UZZAA8lAh4BjzP0DSK9CFQyhbSZG8sWFboM4N32IAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAANdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
            "BQAEAAcABA=="
        >>,
        i2p_keys:to_b64(Id)
    ),
    ?assertEqual(
        <<"42ubplhihknkpc6kp2qk54hwqhpd5tr5ac6h2kitzrnx4d37shcq.b32.i2p">>,
        i2p_keys:to_b32(Id)
    ),
    ?assertEqual({ok, Id}, i2p_keys:from_b64(i2p_keys:to_b64(Id))),
    ?assertEqual(5, i2p_keys:cert_type(Id)),
    ?assertEqual(7, i2p_keys:sig_type(Id)),
    ?assertEqual(4, i2p_keys:crypt_type(Id)).

%%% --------------------------------------------------------------------------
%%% Base64 (I2P alphabet)
%%% --------------------------------------------------------------------------

base64_encode_kat_test() ->
    ?assertEqual(<<>>, i2p_keys:encode_b64(<<>>)),
    ?assertEqual(<<"QQ==">>, i2p_keys:encode_b64(<<"A">>)),
    ?assertEqual(<<"QUI=">>, i2p_keys:encode_b64(<<"AB">>)),
    ?assertEqual(<<"QUJD">>, i2p_keys:encode_b64(<<"ABC">>)),
    ?assertEqual(<<"TWFu">>, i2p_keys:encode_b64(<<"Man">>)),
    %% the two non-standard alphabet chars: - and ~
    ?assertEqual(<<"--~~">>, i2p_keys:encode_b64(<<16#fb, 16#ef, 16#ff>>)).

base64_decode_test() ->
    ?assertEqual(<<"A">>, i2p_keys:decode_b64(<<"QQ==">>)),
    %% padding is optional
    ?assertEqual(<<"A">>, i2p_keys:decode_b64(<<"QQ">>)),
    %% string (character list) input is accepted
    ?assertEqual(<<"A">>, i2p_keys:decode_b64("QQ==")),
    ?assertEqual(<<>>, i2p_keys:decode_b64(<<>>)),
    ?assertEqual(<<>>, i2p_keys:decode_b64(<<"====">>)),
    ?assertError(badarg, i2p_keys:decode_b64(<<"Q!==">>)),
    ?assertError(badarg, i2p_keys:decode_b64(<<"Q">>)),
    ?assertError(badarg, i2p_keys:decode_b64(42)).

base64_roundtrip_test() ->
    lists:foreach(
        fun(Size) ->
            Data = crypto:strong_rand_bytes(Size),
            ?assertEqual(Data, i2p_keys:decode_b64(i2p_keys:encode_b64(Data)))
        end,
        [0, 1, 2, 3, 4, 32, 384, 391, 1000]
    ).

%%% --------------------------------------------------------------------------
%%% Base32 (RFC 4648, lower-case, no padding)
%%% --------------------------------------------------------------------------

base32_kat_test() ->
    ?assertEqual(<<>>, i2p_keys:encode_b32(<<>>)),
    ?assertEqual(<<"my">>, i2p_keys:encode_b32(<<"f">>)),
    ?assertEqual(<<"mzxq">>, i2p_keys:encode_b32(<<"fo">>)),
    ?assertEqual(<<"mzxw6">>, i2p_keys:encode_b32(<<"foo">>)),
    ?assertEqual(<<"mzxw6yq">>, i2p_keys:encode_b32(<<"foob">>)),
    ?assertEqual(<<"mzxw6ytb">>, i2p_keys:encode_b32(<<"fooba">>)),
    ?assertEqual(<<"mzxw6ytboi">>, i2p_keys:encode_b32(<<"foobar">>)).

to_b32_structure_test() ->
    Id = i2p_keys:generate_identity(),
    Addr = i2p_keys:to_b32(Id),
    ?assertEqual(60, byte_size(Addr)),
    <<Enc:52/binary, ".b32.i2p">> = Addr,
    %% the address prefix is the padding-free Base32 of the identity hash
    ?assertEqual(Enc, i2p_keys:encode_b32(i2p_keys:hash(Id))).

%%% --------------------------------------------------------------------------
%%% Rejection paths
%%% --------------------------------------------------------------------------

parse_reject_test() ->
    P = zero_padding(),
    ?assertEqual({error, too_short}, i2p_keys:parse(<<0, 1, 2>>)),
    ?assertEqual({error, badarg}, i2p_keys:parse(42)),
    %% NULL certificate implies the unsupported ElGamal + DSA key pair
    ?assertEqual(
        {error, {unsupported_identity, {0, 0}}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 0, 0, 0>>)
    ),
    %% KEY cert declaring ElGamal + DSA
    ?assertEqual(
        {error, {unsupported_identity, {0, 0}}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 5, 0, 4, 0, 0, 0, 0>>)
    ),
    %% KEY cert with declared length 4 but a shorter payload
    ?assertEqual(
        {error, {bad_cert_length, 4}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 5, 0, 4, 1>>)
    ),
    %% KEY cert with a declared length that doesn't match its payload
    ?assertEqual(
        {error, {bad_cert_length, 9}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 5, 0, 9, 1, 2, 3>>)
    ),
    %% unknown certificate type
    ?assertEqual(
        {error, {unknown_cert_type, 3}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 3, 0, 4, 0, 7, 0, 4>>)
    ),
    %% KEY cert shorter than 4 bytes of payload
    ?assertEqual(
        {error, {unsupported_identity, short_key_cert}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 5, 0, 3, 1, 2, 3>>)
    ),
    %% recognized key types (7, 4) but with extra certificate payload
    ?assertEqual(
        {error, {unsupported_identity, {7, 4}}},
        i2p_keys:parse(<<(cpub())/binary, P/binary, (spub())/binary, 5, 0, 6, 0, 7, 0, 4, 0, 0>>)
    ).

from_b64_error_test() ->
    ?assertEqual({error, badarg}, i2p_keys:from_b64(<<"not-valid!!">>)),
    ?assertEqual({error, badarg}, i2p_keys:from_b64(42)),
    %% decodes fine but is too short to be an identity
    ?assertEqual({error, too_short}, i2p_keys:from_b64(<<"QUJD">>)),
    P = zero_padding(),
    NullB64 = i2p_keys:encode_b64(
        <<(cpub())/binary, P/binary, (spub())/binary, 0, 0, 0>>
    ),
    ?assertEqual(
        {error, {unsupported_identity, {0, 0}}},
        i2p_keys:from_b64(NullB64)
    ).
