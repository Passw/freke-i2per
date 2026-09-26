%% Pure SAM and identity framing tests. They need no application or socket
%% state, so they run as focused EUnit tests; session and tunnel integration
%% behavior is covered by the Common Test suites.

-module(i2p_sam_tests).

-include_lib("eunit/include/eunit.hrl").

generate_with_privkeys_roundtrip_test() ->
    #{identity := Id, crypto_priv := CPriv, sign_priv := SPriv} =
        i2p_keys:generate_with_privkeys(),
    ?assertEqual(391, byte_size(i2p_keys:to_binary(Id))),
    ?assertEqual(32, byte_size(CPriv)),
    ?assertEqual(32, byte_size(SPriv)).

dest_blob_roundtrip_test() ->
    Map = i2p_keys:generate_with_privkeys(),
    Blob = i2p_keys:dest_blob(Map),
    ?assertEqual(455, byte_size(Blob)),
    {ok, Parsed} = i2p_keys:parse_dest_blob(Blob),
    ?assertEqual(i2p_keys:hash(maps:get(identity, Map)), i2p_keys:hash(maps:get(identity, Parsed))),
    ?assertEqual(maps:get(crypto_priv, Map), maps:get(crypto_priv, Parsed)),
    ?assertEqual(maps:get(sign_priv, Map), maps:get(sign_priv, Parsed)).

dest_blob_base64_roundtrip_test() ->
    Map = i2p_keys:generate_with_privkeys(),
    Blob = i2p_keys:dest_blob(Map),
    B64 = i2p_keys:encode_b64(Blob),
    Decoded = i2p_keys:decode_b64(B64),
    {ok, Parsed} = i2p_keys:parse_dest_blob(Decoded),
    ?assertEqual(i2p_keys:hash(maps:get(identity, Map)), i2p_keys:hash(maps:get(identity, Parsed))).

parse_dest_blob_too_short_test() ->
    ?assertEqual({error, bad_dest_blob}, i2p_keys:parse_dest_blob(<<1:80>>)).

parse_dest_blob_empty_test() ->
    ?assertEqual({error, bad_dest_blob}, i2p_keys:parse_dest_blob(<<>>)).
