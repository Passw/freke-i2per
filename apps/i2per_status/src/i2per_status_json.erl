-module(i2per_status_json).

-moduledoc """
Cowboy handler for `GET /status.json`: the current snapshot as JSON. Always
answers 200 — `online` tells the client whether the data is live.
""".

-export([init/2]).

init(Req0, State) ->
    Snap = i2per_status_state:snapshot(),
    Req = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"application/json">>},
        json(Snap),
        Req0
    ),
    {ok, Req, State}.

json(Snap) ->
    json:encode(to_jsonable(Snap)).

%% Snapshot atoms → binary keys for stable wire output.
to_jsonable(Map) when is_map(Map) ->
    maps:from_list(
        [{atom_to_binary(K, utf8), to_jsonable(V)} || {K, V} <- maps:to_list(Map)]
    );
to_jsonable(Node) when is_atom(Node) andalso Node =/= true andalso Node =/= false ->
    atom_to_binary(Node, utf8);
to_jsonable(Value) ->
    Value.
