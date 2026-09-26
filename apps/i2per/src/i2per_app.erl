-module(i2per_app).

-moduledoc """
The i2per OTP application callback.

Starts the top-level supervisor `m:i2per_sup`. Before the tree comes up,
`f:i2p_config:load_default/0` applies an optional `i2per.conf` (fail-closed:
a malformed or unknown entry aborts boot). The supervisor owns the NetDb,
transport listeners and connection supervisors, peer and tunnel managers,
lookup and address-book services, the event bus, and the SAM services.
""".

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    case i2p_config:load_default() of
        ok ->
            i2per_sup:start_link();
        {error, Reason} ->
            erlang:error({config, Reason})
    end.

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
