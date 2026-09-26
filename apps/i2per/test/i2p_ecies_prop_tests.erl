-module(i2p_ecies_prop_tests).

%% Property tests for the ECIES tunnel build-request helpers.
%%
%% Invariants under test:
%%   - truncated_identity_hash/1 returns exactly the first 16 bytes of the
%%     RouterIdentity hash (the hop identifier prefix)

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

truncated_identity_hash_prop_test() ->
    ?assertEqual(
        true,
        proper:quickcheck(
            ?FORALL(
                Hash,
                binary(32),
                begin
                    Trunc = i2p_ecies:truncated_identity_hash(Hash),
                    <<Prefix:16/binary, _/binary>> = Hash,
                    byte_size(Trunc) =:= 16 andalso Trunc =:= Prefix
                end
            ),
            [{numtests, 200}]
        )
    ).
