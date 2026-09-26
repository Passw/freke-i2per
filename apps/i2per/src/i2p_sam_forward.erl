-module(i2p_sam_forward).

-moduledoc """
STREAM FORWARD relay machinery for `m:i2p_sam_session`.

A FORWARD session stays in line mode for its whole life and may relay any
number of concurrent peer streams: every inbound peer stream is answered by
an accept-role `m:i2p_stream_conn` whose payload is piped to a fresh local
TCP connection at the bound host:port — one relay per peer stream.

The session owns the socket-driving `handle_info` clause; when its state
carries live relays (`fwd_relays` non-empty) it hands the raw message here.
`f:info/2` returns a gen_server reply tuple for messages belonging to a
relay, or `unhandled` so the session falls through to its ordinary
single-stream handling.

Relay lifecycle:

- `f:add_relay/3` registers a freshly spawned accept-role connection whose
  local socket is not dialled yet (`sock => undefined`).
- On `{stream_established, Conn, _}` the local service is dialled; a refused
  dial answers the peer with a graceful CLOSE instead of a relay.
- `{tcp, _, _}` / `{stream_data, Conn, _}` pipe bytes in both directions;
  close/reset/'DOWN' from either side tears the relay down via
  `f:drop_relay/2` (demonitor + close the local socket).

## Usage

Called by `m:i2p_sam_session` only:

```erlang
handle_info(Msg, #{fwd_relays := Relays} = State) when map_size(Relays) > 0 ->
    case i2p_sam_forward:info(Msg, State) of
        unhandled -> handle_plain_info(Msg, State);
        Reply -> Reply
    end;
```
""".

-export([
    info/2,
    add_relay/3
]).

-doc """
One FORWARD relay: the streaming connection's monitor plus the local socket
dialled once the handshake completed (`sock` is `undefined` while dialling).
""".
-type fwd_relay() :: #{
    mon := reference(),
    sock => gen_tcp:socket() | undefined
}.

%%%%%%% %%% Public API %%%%%%%

-doc """
Handle one `handle_info` message on behalf of live FORWARD relays.

Input: `Msg` — the raw gen_server message; `State` — the session state with
a non-empty `fwd_relays` map.
Output: `{noreply, State}` or `{stop, normal, State}` when the message
belonged to a relay; `unhandled` when it did not (the caller re-dispatches).
""".
-spec info(term(), i2p_sam_session:state()) ->
    {noreply, i2p_sam_session:state()}
    | {stop, normal, i2p_sam_session:state()}
    | unhandled.
info({tcp, Sock, Data}, State) ->
    #{fwd_relays := Relays} = State,
    case relay_by_sock(Sock, Relays) of
        {ok, Conn} ->
            i2p_stream_conn:send(Conn, Data),
            ok = inet:setopts(Sock, [{active, once}]),
            {noreply, State};
        error ->
            unhandled
    end;
info({tcp_closed, Sock}, State) ->
    #{fwd_relays := Relays} = State,
    case relay_by_sock(Sock, Relays) of
        {ok, Conn} ->
            %% Local service hung up: close the peer stream gracefully.
            i2p_stream_conn:close(Conn),
            {noreply, drop_relay(Conn, State)};
        error ->
            unhandled
    end;
info({tcp_error, Sock, _Reason}, State) ->
    #{fwd_relays := Relays} = State,
    case relay_by_sock(Sock, Relays) of
        {ok, Conn} ->
            i2p_stream_conn:close(Conn),
            {noreply, drop_relay(Conn, State)};
        error ->
            unhandled
    end;
info({stream_established, Conn, _PeerHash}, State) ->
    #{fwd_relays := Relays} = State,
    case maps:find(Conn, Relays) of
        error ->
            unhandled;
        {ok, _Relay} ->
            %% Handshake complete: dial the bound local service for this
            %% stream.
            #{forward := #{host := Host, port := Port}} = State,
            ConnectOpts = [binary, {packet, raw}, {active, once}, {nodelay, true}],
            case gen_tcp:connect(Host, Port, ConnectOpts, 5000) of
                {ok, Sock} ->
                    Relay = maps:get(Conn, Relays),
                    {noreply, State#{fwd_relays => Relays#{Conn => Relay#{sock => Sock}}}};
                {error, _DialReason} ->
                    %% Local service refused: answer the peer with a graceful
                    %% CLOSE.
                    i2p_stream_conn:close(Conn),
                    {noreply, drop_relay(Conn, State)}
            end
    end;
info({stream_started, Conn, MyId}, State) ->
    #{fwd_relays := Relays} = State,
    case maps:is_key(Conn, Relays) of
        false ->
            unhandled;
        true ->
            %% The relay announces its stream ID — the demux key routing
            %% inbound packets to it, same as the CONNECT-side registration.
            i2p_sam_sup:stream_conn_register(maps:get(dest_hash, State), MyId, Conn),
            {noreply, State}
    end;
info({stream_data, Conn, Bytes}, State) ->
    #{fwd_relays := Relays} = State,
    case maps:is_key(Conn, Relays) of
        false ->
            unhandled;
        true ->
            #{sock := Sock} = maps:get(Conn, Relays),
            ok = gen_tcp:send(Sock, Bytes),
            {noreply, State}
    end;
info({stream_closed, Conn}, State) ->
    drop_if_relay(Conn, State);
info({stream_reset, Conn}, State) ->
    drop_if_relay(Conn, State);
info({'DOWN', _Mon, process, Conn, _Reason}, State) ->
    %% Streaming connection died: reclaim its local socket.
    drop_if_relay(Conn, State);
info(_Msg, _State) ->
    unhandled.

-doc """
Register a freshly spawned accept-role connection as an undialled relay.

Input: `ConnPid` — the streaming connection; `Mon` — its monitor;
`State` — the session state. Output: the state with the relay added to
`fwd_relays`.
""".
-spec add_relay(pid(), reference(), i2p_sam_session:state()) -> i2p_sam_session:state().
add_relay(ConnPid, Mon, State) ->
    Relays = maps:get(fwd_relays, State, #{}),
    State#{fwd_relays => Relays#{ConnPid => #{mon => Mon, sock => undefined}}}.

%%%%%%% %%% Internal %%%%%%%

%% drop_if_relay/2 — tear down the relay for `Conn` when one exists;
%% otherwise the message belongs to the session's single-stream handling.
-spec drop_if_relay(pid(), i2p_sam_session:state()) ->
    {noreply, i2p_sam_session:state()} | unhandled.
drop_if_relay(Conn, State) ->
    #{fwd_relays := Relays} = State,
    case maps:is_key(Conn, Relays) of
        true -> {noreply, drop_relay(Conn, State)};
        false -> unhandled
    end.

%% relay_by_sock/2 — the relay whose local socket is `Sock`, if any.
-spec relay_by_sock(gen_tcp:socket(), #{pid() => fwd_relay()}) -> {ok, pid()} | error.
relay_by_sock(Sock, Relays) ->
    case [Conn || {Conn, #{sock := S}} <- maps:to_list(Relays), S =:= Sock] of
        [Conn | _] -> {ok, Conn};
        [] -> error
    end.

%% drop_relay/2 — tear down one FORWARD relay: cancel its monitor, close its
%% local socket (when dialled) and remove it from the session state.
-spec drop_relay(pid(), i2p_sam_session:state()) -> i2p_sam_session:state().
drop_relay(Conn, State) ->
    Relays = maps:get(fwd_relays, State),
    case maps:find(Conn, Relays) of
        {ok, #{mon := Mon, sock := Sock}} ->
            erlang:demonitor(Mon, [flush]),
            case Sock of
                undefined -> ok;
                _ -> gen_tcp:close(Sock)
            end;
        error ->
            ok
    end,
    State#{fwd_relays => maps:remove(Conn, Relays)}.
