-module(i2p_ssu2_sup).

-moduledoc """
Supervisor owning every SSU2 session and listener, plus the session registry.

Children are started on demand and are all `temporary`: a session that dies —
for any reason — is never restarted and never hot-loops, and its death cannot
take the supervisor (or the listener, or any sibling) down. The supervisor is
a child of `m:i2per_sup`; tests start it directly.

The public ETS table `i2p_ssu2_sessions` maps destination connection ID to
session pid; `f:i2p_ssu2_listener/1` consults it for inbound classification
and sessions are removed by their monitor in `m:i2p_ssu2_listener`. The public
table `i2p_ssu2_relay_tags` maps a handed-out 32-bit relay tag to the session
pid that holds it (plus its expiry); rows are written by the listener's
`f:i2p_ssu2_listener:register_relay_tag/4` cast at the introducer's request
and removed when the session dies.
""".

-behaviour(supervisor).

-define(DEFAULT_MAX_SESSIONS, 32).

-export([
    start_link/0,
    start_link/4,
    session_child/1,
    start_session/1,
    session_count/0,
    session_limit/0,
    session_limit_reached/0,
    init/1
]).

-doc "Start the supervisor, registered locally as `i2p_ssu2_sup`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    bootstrap_tables(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start the supervisor with a permanent SSU2 boot listener bound on `Host`:`Port`.

Used by the persistent (operator) boot of `m:i2per_sup`; the listener is owned
by `m:i2p_peer`. `LocalKeys` is the `m:i2p_ssu2_conn` local map (must carry
`intro_key`).
""".
-spec start_link(
    inet:ip_address() | binary() | string(),
    0..65535,
    i2p_ssu2_conn:local_keys(),
    pid()
) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, LocalKeys, Owner) ->
    bootstrap_tables(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Host, Port, LocalKeys, Owner]).

bootstrap_tables() ->
    case ets:whereis(i2p_ssu2_sessions) of
        undefined ->
            _ = ets:new(
                i2p_ssu2_sessions,
                [named_table, public, set, {read_concurrency, true}]
            ),
            _ = ets:new(
                i2p_ssu2_pending,
                [named_table, public, set, {read_concurrency, true}]
            ),
            _ = ets:new(
                i2p_ssu2_relay_tags,
                [named_table, public, set, {read_concurrency, true}]
            ),
            ok;
        _Existing ->
            ok
    end.

-doc """
A `temporary` worker child spec for one session process
(`t:i2p_ssu2_conn:config/0`).
""".
-spec session_child(i2p_ssu2_conn:config()) -> supervisor:child_spec().
session_child(Args) ->
    #{
        id => {ssu2_conn, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ssu2_conn, start_link, [Args]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ssu2_conn]
    }.

-doc """
Admit and start one SSU2 session under the configured active-session limit.

The admission check and `supervisor:start_child/2` are serialized with a node
lock so simultaneous inbound/outbound handshakes cannot exceed the limit.
Output is the normal `supervisor:start_child/2` result, or
`{error, session_limit}`.
""".
-spec start_session(supervisor:child_spec()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_session(ChildSpec) ->
    global:trans(
        {?MODULE, session_admission},
        fun() ->
            case session_limit_reached() of
                true -> {error, session_limit};
                false -> supervisor:start_child(?MODULE, ChildSpec)
            end
        end
    ).

-doc "Return the number of active SSU2 session workers.".
-spec session_count() -> non_neg_integer().
session_count() ->
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
                element(1, Id) =:= ssu2_conn
            ])
    end.

-doc """
Return the maximum number of active SSU2 sessions.

The default is 32 and can be overridden with the restart-required
`max_ssu2_sessions` application setting. A zero value is an emergency
fail-closed switch that rejects all new sessions.
""".
-spec session_limit() -> non_neg_integer().
session_limit() ->
    case application:get_env(i2per, max_ssu2_sessions) of
        {ok, Value} when is_integer(Value), Value >= 0 -> Value;
        _ -> ?DEFAULT_MAX_SESSIONS
    end.

-doc "Whether a new SSU2 session would exceed the configured limit.".
-spec session_limit_reached() -> boolean().
session_limit_reached() ->
    session_count() >= session_limit().

init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, []}};
init([Host, Port, LocalKeys, Owner]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 10, period => 10}, [
            #{
                id => {ssu2_listener, Port, erlang:unique_integer([positive, monotonic])},
                start =>
                    {i2p_ssu2_listener, start_link, [Host, Port, LocalKeys, Owner, undefined]},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2p_ssu2_listener]
            }
        ]}}.
