-module(i2p_tunnel_srv_stub).

-moduledoc """
Minimal `m:i2p_tunnel_srv` stand-in for EUnit tests that must cross its
registered interface (`publish_lease_set/2`, `status/0`) without booting a
real router. Registered under the tunnel manager's local name;
`start/0`/`stop/0` are idempotent so several test functions in a module can
share one instance.
""".

-behaviour(gen_server).

-export([start/0, stop/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

start() ->
    case whereis(i2p_tunnel_srv) of
        undefined ->
            {ok, _Pid} = gen_server:start_link({local, i2p_tunnel_srv}, ?MODULE, [], []),
            ok;
        _Pid ->
            ok
    end.

stop() ->
    case whereis(i2p_tunnel_srv) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

init([]) ->
    {ok, #{}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.
