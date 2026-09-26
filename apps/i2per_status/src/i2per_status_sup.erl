-module(i2per_status_sup).

-moduledoc """
Supervisor of the `i2per_status` web service.

Owns the snapshot server (`m:i2per_status_state`) and the cowboy listener
(started in init so its lifetime is bound to this supervisor: application
stop takes the HTTP endpoint down with the tree). The listener binds to
`i2per_status` -> `listen_host` and defaults to loopback.
""".

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-doc "Start the supervisor. Called only by `m:i2per_status_app`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    ok = start_listener(),
    {ok,
        {#{strategy => one_for_one, intensity => 5, period => 10}, [
            #{
                id => i2per_status_state,
                start => {i2per_status_state, start_link, []},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_status_state]
            }
        ]}}.

%% Bind the HTTP listener here: linked to the supervisor, named so restarts
%% replace any lingering instance deterministically.
start_listener() ->
    Port = application:get_env(i2per_status, port, 7662),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/", i2per_status_page, []},
            {"/status.json", i2per_status_json, []}
        ]}
    ]),
    case open_listener(Port, Dispatch) of
        ok ->
            ok;
        {error, {already_started, _}} ->
            %% A previous instance (old port) is still around: replace it.
            ok = cowboy:stop_listener(i2per_status_http),
            case open_listener(Port, Dispatch) of
                ok -> ok;
                {error, Reason} -> erlang:error({status_listener, Reason})
            end;
        {error, Reason} ->
            erlang:error({status_listener, Reason})
    end.

open_listener(Port, Dispatch) ->
    ListenIP = listen_ip(),
    case
        cowboy:start_clear(
            i2per_status_http,
            [{port, Port}, {ip, ListenIP}],
            #{env => #{dispatch => Dispatch}}
        )
    of
        {ok, _Pid} ->
            ok;
        {error, _} = Err ->
            Err
    end.

listen_ip() ->
    case application:get_env(i2per_status, listen_host, {127, 0, 0, 1}) of
        {127, _, _, _} = IP ->
            IP;
        {0, 0, 0, 0} = IP ->
            IP;
        IP when is_tuple(IP), tuple_size(IP) =:= 8 ->
            IP;
        Host when is_binary(Host) ->
            case inet:parse_address(binary_to_list(Host)) of
                {ok, IP} -> IP;
                {error, _} -> erlang:error({status_listener, {invalid_listen_host, Host}})
            end;
        Other ->
            erlang:error({status_listener, {invalid_listen_host, Other}})
    end.
