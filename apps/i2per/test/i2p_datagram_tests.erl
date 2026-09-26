%% Repliable (Datagram1) datagram codec. Round-trip preserves sender
%% destination and payload; the Ed25519 signature binds the payload, so any
%% tampering, foreign sender, truncation, or bad destination length fails
%% closed (error).

-module(i2p_datagram_tests).

-include_lib("eunit/include/eunit.hrl").

datagram_codec_test_() ->
    [
        {"round-trip keeps sender destination and payload", fun roundtrip/0},
        {"tampered payload fails authentication", fun tampered/0},
        {"signature by another key fails", fun foreign_signer/0},
        {"malformed frames fail closed", fun malformed/0}
    ].

roundtrip() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    Payload = <<"ping over tunnels">>,
    {ok, Wire} = i2p_datagram:encode(FromBin, Seed, Payload),
    ?assertEqual(391 + 64 + byte_size(Payload), byte_size(Wire)),
    {ok, #{from := FromBin, payload := Payload}} = i2p_datagram:decode(Wire).

tampered() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    {ok, Wire} = i2p_datagram:encode(i2p_keys:to_binary(Id), Seed, <<"attack at dawn">>),
    HeadSize = 391 + 64,
    <<Head:HeadSize/binary, P, Rest/binary>> = Wire,
    ?assertEqual(error, i2p_datagram:decode(<<Head/binary, (P bxor 16#FF), Rest/binary>>)).

foreign_signer() ->
    #{sign_priv := SeedA} = i2p_keys:generate_with_privkeys(),
    #{identity := IdB} = i2p_keys:generate_with_privkeys(),
    %% Signed by A but claims B as sender: the embedded signature does not
    %% verify against B's public signing key.
    {ok, Wire} = i2p_datagram:encode(i2p_keys:to_binary(IdB), SeedA, <<"spoof">>),
    ?assertEqual(error, i2p_datagram:decode(Wire)).

malformed() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    {ok, Wire} = i2p_datagram:encode(FromBin, Seed, <<"payload">>),
    %% Truncated below from+signature minimum
    ?assertEqual(error, i2p_datagram:decode(binary:part(Wire, 0, 400))),
    ?assertEqual(error, i2p_datagram:decode(<<>>)),
    ?assertEqual(error, i2p_datagram:decode(<<0, 1, 2, 3>>)),
    %% Non-binary input
    ?assertEqual(error, i2p_datagram:decode(wrong)),
    %% Sender destination must be a full 391-byte binary
    ?assertEqual(error, i2p_datagram:encode(<<0:16/unit:8>>, Seed, <<"x">>)).
