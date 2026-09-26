-module(i2per_status_page_tests).

-moduledoc """
Tests for the pure HTML rendering of `m:i2per_status_page`: online table,
offline notice, and the `n/a` fallbacks when snapshot sections are missing.
""".

-include_lib("eunit/include/eunit.hrl").

full_snapshot() ->
    #{
        online => true,
        identity => <<"abc123">>,
        peers => #{connected => 3, other => 2},
        tunnels => #{outbound => 1, inbound => 2, transit => 4},
        netdb => #{ri => 9, ls => 0},
        sessions => 5
    }.

online_renders_report_table_test() ->
    Body = render(full_snapshot()),
    asserts(
        [
            <<"identity: <code>abc123</code>">>,
            <<"<tr><td>peers connected</td><td>3</td></tr>">>,
            <<"<tr><td>tunnels outbound</td><td>1</td></tr>">>,
            <<"<tr><td>tunnels inbound</td><td>2</td></tr>">>,
            <<"<tr><td>transit tunnels</td><td>4</td></tr>">>,
            <<"<tr><td>netdb router infos</td><td>9</td></tr>">>,
            <<"<tr><td>netdb leasesets</td><td>0</td></tr>">>,
            <<"<tr><td>SAM sessions</td><td>5</td></tr>">>
        ],
        Body
    ),
    ?assertNotEqual(nomatch, binary:match(Body, <<"</table>">>)).

offline_renders_notice_test() ->
    Body = render(#{online => false}),
    ?assertNotEqual(nomatch, binary:match(Body, <<"<b>router offline</b>">>)).

missing_sections_render_na_test() ->
    %% Every section absent: count/3 and sessions/1 hit their `n/a` paths.
    Body = render(#{online => true}),
    asserts(
        [
            <<"<td>n/a</td>">>
        ],
        Body
    ),
    ?assertEqual(7, row_count(Body, <<"<td>n/a</td>">>)).

non_integer_sessions_render_na_test() ->
    Snap = (full_snapshot())#{sessions => <<"unknown">>},
    Body = render(Snap),
    ?assertNotEqual(nomatch, binary:match(Body, <<"<td>n/a</td>">>)),
    ?assertEqual(nomatch, binary:match(Body, <<">unknown<</td>">>)).

render(Snap) ->
    iolist_to_binary(i2per_status_page:html(Snap)).

asserts(Needles, Body) ->
    lists:foreach(
        fun(N) -> ?assertNotEqual(nomatch, binary:match(Body, N)) end, Needles
    ).

row_count(Body, Needle) ->
    length(binary:matches(Body, Needle)).
