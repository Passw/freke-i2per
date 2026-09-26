-module(i2per_status_app).

-moduledoc """
The `i2per_status` OTP application callback.

Standalone web service exposing the state of a running `i2per` router over
HTTP. It is deliberately **not** started together with the router and holds no
boot-time dependency on it: operators start and stop it explicitly with
`application:ensure_all_started(i2per_status)` / `application:stop(i2per_status)`
on any Erlang node connected to the router's node (or on the router node
itself). When the router is absent the service still boots and renders an
offline page.
""".

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()}.
start(_Type, _Args) ->
    i2per_status_sup:start_link().

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
