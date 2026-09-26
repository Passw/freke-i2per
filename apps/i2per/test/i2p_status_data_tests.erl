-module(i2p_status_data_tests).

-moduledoc """
Tests for the `m:i2p_status_data` peer-status aggregation: only `connected`
states count toward connected, everything else lands in `other`.
""".

-include_lib("eunit/include/eunit.hrl").

empty_peers_test() ->
    ?assertEqual(#{connected => 0, other => 0}, i2p_status_data:aggregate_peers(#{})).

only_connected_test() ->
    Status = #{
        <<"a">> => #{status => connected},
        <<"b">> => #{status => connected}
    },
    ?assertEqual(
        #{connected => 2, other => 0},
        i2p_status_data:aggregate_peers(Status)
    ).

mixed_states_test() ->
    Status = #{
        <<"a">> => #{status => connected},
        <<"b">> => #{status => idle},
        <<"c">> => #{status => failed},
        <<"d">> => #{status => excluded}
    },
    ?assertEqual(
        #{connected => 1, other => 3},
        i2p_status_data:aggregate_peers(Status)
    ).

no_connected_test() ->
    Status = #{<<"a">> => #{status => idle}, <<"b">> => #{}},
    ?assertEqual(
        #{connected => 0, other => 2},
        i2p_status_data:aggregate_peers(Status)
    ).
