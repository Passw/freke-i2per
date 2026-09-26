-module(i2p_sam_listener).

-moduledoc """
SAM v3 TCP listener: accepts incoming SAM connections and spawns one
`m:i2p_sam_session` per accepted socket.

Sessions are spawned by `m:i2p_sam_listener` and are not started directly.

The listener is a `temporary` child of `m:i2p_sam_sup`. In the persistent
(operator) boot it is started automatically — bound on the `i2per` ->
`sam_port` app env — while explicit/test boots start it on demand via
`f:listen/1`. Accepted sockets are handed to a fresh session process under
the same supervisor, so a session's death — even by `kill` — leaves the
listener and every sibling session alive.

## Usage

```erlang
{ok, Listener} = i2p_sam_listener:listen(#{port => 7656}),
Port = i2p_sam_listener:port(Listener),
ok = i2p_sam_listener:stop(Listener).
```
""".

-export([listen/1, port/1, address/1, stop/1, start_link/1, init/1]).

-doc """
Start a SAM listener on the given port.

Input: `Opts` — a map with keys `port` (default 7656) and `local`
(`t:i2p_peer:local_keys/0`, required).
Output: `{ok, Pid}`.
""".
-spec listen(map()) -> {ok, pid()}.
listen(#{local := _Local} = Opts) ->
    supervisor:start_child(i2p_sam_sup, i2p_sam_sup:listener_child(Opts)).

-doc "The bound local port of the listener.".
-spec port(pid()) -> inet:port_number().
port(Listener) ->
    Ref = make_ref(),
    Listener ! {port, self(), Ref},
    receive
        {port, Ref, P} -> P
    end.

-doc """
Return the local address on which the listener is bound.

Input: a listener pid. Output: the bound IP address.
""".
-spec address(pid()) -> inet:ip_address().
address(Listener) ->
    Ref = make_ref(),
    Listener ! {address, self(), Ref},
    receive
        {address, Ref, Address} -> Address
    end.

-doc "Stop accepting new connections; existing sessions are unaffected.".
-spec stop(pid()) -> ok.
stop(Listener) ->
    Ref = make_ref(),
    Listener ! {stop, self(), Ref},
    receive
        {stopped, Ref} -> ok
    end.

-doc false.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    proc_lib:start_link(?MODULE, init, [Opts]).

-doc false.
-dialyzer({no_underspecs, init/1}).
-spec init(map()) -> no_return().
init(#{port := Port, local := Local} = _Opts) ->
    ListenIP = i2p_config:listen_ip(),
    {ok, ListenSock} = gen_tcp:listen(
        Port,
        [
            binary,
            {packet, raw},
            {active, false},
            {reuseaddr, true},
            {nodelay, true},
            {ip, ListenIP}
        ]
    ),
    {ok, BoundPort} = inet:port(ListenSock),
    proc_lib:init_ack({ok, self()}),
    accept_loop(ListenSock, BoundPort, ListenIP, Local).

accept_loop(ListenSock, BoundPort, ListenIP, Local) ->
    receive
        {port, From, Ref} ->
            From ! {port, Ref, BoundPort},
            accept_loop(ListenSock, BoundPort, ListenIP, Local);
        {address, From, Ref} ->
            From ! {address, Ref, ListenIP},
            accept_loop(ListenSock, BoundPort, ListenIP, Local);
        {stop, From, Ref} ->
            From ! {stopped, Ref},
            exit(normal)
    after 1000 ->
        case gen_tcp:accept(ListenSock, 0) of
            {ok, Sock} ->
                ok = inet:setopts(Sock, [{nodelay, true}, {keepalive, true}]),
                Args = #{sock => Sock, local => Local},
                case i2p_sam_sup:start_session(i2p_sam_sup:session_child(Args)) of
                    {ok, SessionPid} ->
                        ok = gen_tcp:controlling_process(Sock, SessionPid),
                        SessionPid ! {socket_ready, Sock},
                        accept_loop(ListenSock, BoundPort, ListenIP, Local);
                    {ok, SessionPid, _Extra} ->
                        ok = gen_tcp:controlling_process(Sock, SessionPid),
                        SessionPid ! {socket_ready, Sock},
                        accept_loop(ListenSock, BoundPort, ListenIP, Local);
                    {error, _Reason} ->
                        ok = gen_tcp:close(Sock),
                        accept_loop(ListenSock, BoundPort, ListenIP, Local)
                end;
            {error, timeout} ->
                accept_loop(ListenSock, BoundPort, ListenIP, Local);
            {error, closed} ->
                exit(normal)
        end
    end.
