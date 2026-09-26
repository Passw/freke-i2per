-module(i2p_ntcp2_listener).

-moduledoc """
The NTCP2 listener: owns a listening socket and spawns one
`m:i2p_ntcp2_conn` (responder, Bob) process per accepted connection.

The listener itself is a `temporary` child of `m:i2p_ntcp2_sup`, started on
demand for a specific local port. Accepted sockets are handed to a fresh Bob
connection process under the same supervisor, so a connection's death — even
by `kill` — leaves the listener and every sibling connection alive. Closing the
listener stops future accepts but does not touch established connections.

## Usage

```erlang
{ok, Listener} = i2p_ntcp2_listener:listen(Port, Local, self()),
Port = i2p_ntcp2_listener:port(Listener),
ok = i2p_ntcp2_listener:stop(Listener).
```
""".

-export([listen/3, port/1, address/1, stop/1, start_link/3, init/3]).

-doc """
Start a listener on `Port` (0 for an ephemeral port) using the node's
`t:i2p_ntcp2_conn:local_keys()`. Accepted connections deliver decrypted frames
to `Owner` as `{ntcp2_frame, ConnPid, Payload}`.
Output: `{ok, Pid}`.
""".
-spec listen(0..65535, i2p_ntcp2_conn:local_keys(), pid()) -> {ok, pid()}.
listen(Port, LocalKeys, Owner) ->
    supervisor:start_child(i2p_ntcp2_sup, i2p_ntcp2_sup:listener_child(Port, LocalKeys, Owner)).

-doc "The bound local port of the listener (useful with port 0).".
-spec port(pid()) -> inet:port_number().
port(Listener) ->
    Ref = make_ref(),
    Listener ! {port, self(), Ref},
    receive
        {port, Ref, P} -> P
    end.

-doc """
Return the local address on which the listener is bound.

Input: a listener pid. Output: the bound IP address, useful for verifying that
an operator did not widen the listener unintentionally.
""".
-spec address(pid()) -> inet:ip_address().
address(Listener) ->
    Ref = make_ref(),
    Listener ! {address, self(), Ref},
    receive
        {address, Ref, Address} -> Address
    end.

-doc "Stop accepting new connections; established connections are unaffected.".
-spec stop(pid()) -> ok.
stop(Listener) ->
    Ref = make_ref(),
    Listener ! {stop, self(), Ref},
    receive
        {stopped, Ref} -> ok
    end.

-doc false.
-spec start_link(0..65535, i2p_ntcp2_conn:local_keys(), pid()) -> {ok, pid()} | {error, term()}.
start_link(Port, LocalKeys, Owner) ->
    proc_lib:start_link(?MODULE, init, [Port, LocalKeys, Owner]).

init(Port, LocalKeys, Owner) ->
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
    accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner).

accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner) ->
    receive
        {port, From, Ref} ->
            From ! {port, Ref, BoundPort},
            accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner);
        {address, From, Ref} ->
            From ! {address, Ref, ListenIP},
            accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner);
        {stop, From, Ref} ->
            From ! {stopped, Ref},
            exit(normal)
    after 1000 ->
        case gen_tcp:accept(ListenSock, 0) of
            {ok, Sock} ->
                ok = inet:setopts(Sock, [{nodelay, true}, {keepalive, true}]),
                Args = #{role => bob, sock => Sock, local => LocalKeys, owner => Owner},
                case i2p_ntcp2_sup:start_connection(i2p_ntcp2_sup:conn_child(Args)) of
                    {ok, Conn} ->
                        %% The socket was accepted by this process, so data-phase
                        %% frames in active mode would arrive here, not in the
                        %% connection process. Hand it over before the connection
                        %% reaches the data phase (its handshake is still in
                        %% flight).
                        ok = gen_tcp:controlling_process(Sock, Conn),
                        accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner);
                    {ok, Conn, _Extra} ->
                        ok = gen_tcp:controlling_process(Sock, Conn),
                        accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner);
                    {error, _Reason} ->
                        ok = gen_tcp:close(Sock),
                        accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner)
                end;
            {error, timeout} ->
                accept_loop(ListenSock, BoundPort, ListenIP, LocalKeys, Owner);
            {error, closed} ->
                exit(normal)
        end
    end.
