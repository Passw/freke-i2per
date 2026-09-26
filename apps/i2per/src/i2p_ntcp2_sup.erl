-module(i2p_ntcp2_sup).

-moduledoc """
Supervisor owning every NTCP2 connection and listener.

Children are started on demand and are all `temporary`: a connection that dies
— for any reason, including `kill` — is never restarted and never hot-loops, and
its death cannot take the supervisor (or the listener, or any sibling
connection) down. The supervisor is a child of `m:i2per_sup`.

`i2p_ntcp2_conn:connect/3` and `i2p_ntcp2_listener:listen/3` build their child
specs through `conn_child/1` and `listener_child/3`.
""".

-behaviour(supervisor).

-define(DEFAULT_MAX_CONNECTIONS, 64).

-export([
    start_link/0,
    start_link/3,
    conn_child/1,
    listener_child/3,
    start_connection/1,
    connection_count/0,
    connection_limit/0,
    connection_limit_reached/0
]).
-export([init/1]).

-doc "Start the supervisor, registered locally as `i2p_ntcp2_sup`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start the supervisor with a boot-time listener bound on `Port` (the operator
boot path, `m:i2per_sup`).

Accepted connections announce to `Owner` (the peer manager) and are children
of this supervisor like any on-demand connection. Unlike the on-demand
`f:listen/3` listener, the boot listener is a `permanent` child: if it dies
the supervisor restarts it, and a listener that cannot bind brings the router
down at boot instead of silently running without ingress.
""".
-spec start_link(0..65535, i2p_ntcp2_conn:local_keys(), pid()) ->
    {ok, pid()} | {error, term()}.
start_link(Port, LocalKeys, Owner) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Port, LocalKeys, Owner]).

-doc """
Admit and start one NTCP2 connection under the configured active-connection
limit.

The admission check and `supervisor:start_child/2` are serialized with a node
lock so simultaneous peer dials cannot exceed the limit. Output is the normal
`supervisor:start_child/2` result, or `{error, connection_limit}`.
""".
-spec start_connection(supervisor:child_spec()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_connection(ChildSpec) ->
    global:trans(
        {?MODULE, connection_admission},
        fun() ->
            case connection_limit_reached() of
                true ->
                    {error, connection_limit};
                false ->
                    supervisor:start_child(?MODULE, ChildSpec)
            end
        end
    ).

-doc "Return the number of active NTCP2 connection workers.".
-spec connection_count() -> non_neg_integer().
connection_count() ->
    case whereis(?MODULE) of
        undefined ->
            0;
        Sup ->
            length([
                Id
             || {Id, Pid, _Type, _Modules} <- supervisor:which_children(Sup),
                is_pid(Pid),
                is_tuple(Id),
                tuple_size(Id) > 0,
                element(1, Id) =:= conn
            ])
    end.

-doc """
Return the maximum number of active NTCP2 connection workers.

The default is 64 and can be overridden with the restart-required
`max_ntcp2_connections` application setting. A zero value is an emergency
fail-closed switch that rejects all new connections.
""".
-spec connection_limit() -> non_neg_integer().
connection_limit() ->
    case application:get_env(i2per, max_ntcp2_connections) of
        {ok, Value} when is_integer(Value), Value >= 0 -> Value;
        _ -> ?DEFAULT_MAX_CONNECTIONS
    end.

-doc "Whether a new NTCP2 connection would exceed the configured limit.".
-spec connection_limit_reached() -> boolean().
connection_limit_reached() ->
    connection_count() >= connection_limit().

-doc """
A `temporary` worker child spec for one connection process.
`handshake_timeout` defaults to 15 seconds.
""".
-spec conn_child(i2p_ntcp2_conn:config()) -> supervisor:child_spec().
conn_child(Args) ->
    Timeout = maps:get(handshake_timeout, Args, 15000),
    #{
        id => {conn, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ntcp2_conn, start_link, [Args#{handshake_timeout => Timeout}]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ntcp2_conn]
    }.

-doc """
A `temporary` worker child spec for one listener. One listener per `Port`.
""".
-spec listener_child(0..65535, i2p_ntcp2_conn:local_keys(), pid()) -> supervisor:child_spec().
listener_child(Port, LocalKeys, Owner) ->
    #{
        id => {listener, Port, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ntcp2_listener, start_link, [Port, LocalKeys, Owner]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ntcp2_listener]
    }.

%% The boot listener: a permanent child so a listener crash is restarted and a
%% bind failure fails the router at boot. Same listener process as above.
boot_listener_child(Port, LocalKeys, Owner) ->
    (listener_child(Port, LocalKeys, Owner))#{restart => permanent}.

init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10}, []}};
init([Port, LocalKeys, Owner]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 5, period => 10}, [
            boot_listener_child(Port, LocalKeys, Owner)
        ]}}.
