-module(i2per_status_page).

-moduledoc """
Cowboy handler for `GET /`: an HTML dashboard of the observed
router's state. Renders an offline notice when the router is unreachable.
""".

-export([init/2, html/1]).

init(Req0, State) ->
    Snap = i2per_status_state:snapshot(),
    Req = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"text/html; charset=utf-8">>},
        html(Snap),
        Req0
    ),
    {ok, Req, State}.

-doc """
Render the complete HTML dashboard from a `t:i2per_status_state:snapshot/0`.

Input: the snapshot returned by `i2per_status_state:snapshot/0`. Output: an
iolist; the offline branch renders the "router offline" notice. Exported so
the pure rendering can be unit-tested without a live Cowboy request.
""".
-spec html(map()) -> iolist().
html(#{online := true} = Snap) ->
    [
        <<
            "<!DOCTYPE html><html><head><title>i2per status</title></head><body>"
            "<h1>i2per router</h1>"
            "<p>identity: <code>"
        >>,
        maps:get(identity, Snap, <<"-">>),
        <<
            "</code></p>"
            "<table border=\"1\">"
            "<tr><th>metric</th><th>value</th></tr>"
        >>,
        rows(Snap),
        <<"</table></body></html>">>
    ];
html(_Snap) ->
    [
        <<
            "<!DOCTYPE html><html><head><title>i2per status</title></head><body>"
            "<h1>i2per router</h1><p><b>router offline</b></p></body></html>"
        >>
    ].

rows(Snap) ->
    Flat =
        [
            {"peers connected", count(Snap, peers, connected)},
            {"tunnels outbound", count(Snap, tunnels, outbound)},
            {"tunnels inbound", count(Snap, tunnels, inbound)},
            {"transit tunnels", count(Snap, tunnels, transit)},
            {"netdb router infos", count(Snap, netdb, ri)},
            {"netdb leasesets", count(Snap, netdb, ls)},
            {"SAM sessions", sessions(Snap)}
        ],
    [
        ["<tr><td>", K, "</td><td>", V, "</td></tr>"]
     || {K, V} <- Flat
    ].

count(Snap, Section, Key) ->
    case maps:find(Section, Snap) of
        {ok, Sub} -> integer_to_binary(maps:get(Key, Sub, 0));
        error -> <<"n/a">>
    end.

sessions(Snap) ->
    case maps:find(sessions, Snap) of
        {ok, N} when is_integer(N) -> integer_to_binary(N);
        _ -> <<"n/a">>
    end.
