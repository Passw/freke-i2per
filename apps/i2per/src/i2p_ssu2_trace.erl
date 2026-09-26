-module(i2p_ssu2_trace).

-moduledoc """
Opt-in on-wire observability for the SSU2 transport.

When a collector process is registered as `i2p_ssu2_trace_sink` — e.g. by
`i2p_ct_helpers:start_ssu2_trace/0` — the SSU2 session (`m:i2p_ssu2_conn`), its
listener (`m:i2p_ssu2_listener`) and the PeerTest coordinator
(`m:i2p_peertest_coord`) emit `{ssu2_trace, MonotonicMs, Pid, Label, Details}`
messages to it. With no collector registered, an `f:emit/3` call is a single
registered-name lookup plus a no-op.

When enabled, the trace records enough detail to distinguish a sender that
never emitted a packet, a datagram lost between the listener and session, and
a receiver that decoded but did not forward a block. It is diagnostic only:
no production path depends on it, and it carries no protocol state.
""".

-export([emit/3, sink/0, disable/0]).

-define(SINK, i2p_ssu2_trace_sink).

-doc """
Emit one trace event. No-op when no collector is registered; otherwise the
event is sent to it as `{ssu2_trace, MonotonicMs, Pid, Label, Details}` where
`MonotonicMs` is the OTP monotonic clock in milliseconds. `Label` is a free-form
diagnostic tag (an atom or any shaped tuple); it is only ever forwarded to a
registered collector for debugging, so it is typed loosely on purpose.
""".
-spec emit(pid(), atom() | tuple(), term()) -> ok.
emit(Pid, Label, Details) ->
    case whereis(?SINK) of
        Collector when is_pid(Collector) ->
            _ = Collector ! {ssu2_trace, erlang:monotonic_time(millisecond), Pid, Label, Details},
            ok;
        _NoCollector ->
            ok
    end.

-doc "The registered collector, or `undefined` when tracing is disabled.".
-spec sink() -> pid() | port() | undefined.
sink() ->
    whereis(?SINK).

-doc "Unregister the trace collector (no-op when tracing is disabled).".
-spec disable() -> ok.
disable() ->
    case whereis(?SINK) of
        undefined ->
            ok;
        _Registered ->
            unregister(?SINK),
            ok
    end.
