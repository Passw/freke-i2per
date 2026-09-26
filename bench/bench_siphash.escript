#!/usr/bin/env escript

%% Micro-benchmark for the pure-Erlang SipHash-2-4. Sizes measured:
%%   8 bytes  - the NTCP2 frame-length obfuscation input is a 64-bit IV
%%   64 bytes - representative of hashing a full NTCP2 header block
%% Report ops/sec and µs/op.

main(_) ->
    Script = filename:absname(escript:script_name()),
    Root = filename:dirname(filename:dirname(Script)),
    Ebin = filename:join([Root, "_build", "default", "lib", "i2per", "ebin"]),
    true = code:add_patha(Ebin),
    Key = list_to_binary(lists:seq(0, 15)),
    Data8 = binary:copy(<<16#de, 16#ad, 16#be, 16#ef, 16#ca, 16#fe, 16#ba, 16#be>>, 1),
    Data64 = binary:copy(<<16#de, 16#ad, 16#be, 16#ef, 16#ca, 16#fe, 16#ba, 16#be>>, 8),
    io:format("pure-Erlang SipHash-2-4~n"),
    io:format("~-12s ~14s ~12s~n", ["input", "ops/sec", "µs/op"]),
    report("8 bytes (NTCP2)", fun() -> i2p_siphash:hash_le(Data8, Key) end, 1000000),
    report("64 bytes", fun() -> i2p_siphash:hash_le(Data64, Key) end, 500000),
    report("8 bytes (128-bit)", fun() -> i2p_siphash:hash_128_le(Data8, Key) end, 500000),
    ok.

report(Label, Fun, N) ->
    Fun(),
    T0 = erlang:monotonic_time(microsecond),
    run_loop(Fun, N),
    T1 = erlang:monotonic_time(microsecond),
    Us = T1 - T0,
    OpsPerSec = round(N * 1000000 / Us),
    io:format("~-12s ~14B ~12.1f~n", [Label, OpsPerSec, Us / N]).

run_loop(_Fun, 0) -> ok;
run_loop(Fun, N) -> Fun(), run_loop(Fun, N - 1).
