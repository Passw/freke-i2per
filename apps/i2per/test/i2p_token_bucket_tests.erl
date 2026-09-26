-module(i2p_token_bucket_tests).

%% Deterministic unit tests for i2p_token_bucket: time is passed in
%% explicitly, so no wall clock or sleep is involved.

-include_lib("eunit/include/eunit.hrl").

c(Bucket, N, NowMs) ->
    i2p_token_bucket:consume(Bucket, N, NowMs).

%% A full bucket conforms immediately; refills accrue continuously.
refill_accumulates_test() ->
    B0 = i2p_token_bucket:new(1000, 1000),
    {allow, B1} = c(B0, 1000, 0),
    %% 500ms later exactly a half-second's worth has accrued
    {allow, B2} = c(B1, 500, 500),
    %% ... and nothing more until the clock ticks again
    deny = c(B2, 1, 500),
    {allow, _B3} = c(B2, 1, 501).

%% Accrual is bounded by the capacity: idle time never stockpiles beyond
%% the burst size.
capacity_caps_stockpile_test() ->
    B0 = i2p_token_bucket:new(1000, 1000),
    {allow, B1} = c(B0, 1000, 0),
    %% two seconds idle, but only one second's worth is usable
    {allow, B2} = c(B1, 1000, 2000),
    deny = c(B2, 1, 2000).

%% A fresh bucket hands out the full burst without waiting for refill.
burst_always_passes_test() ->
    B0 = i2p_token_bucket:new(500, 500),
    {allow, B1} = c(B0, 100, 0),
    {allow, B2} = c(B1, 100, 10),
    {allow, B3} = c(B2, 100, 20),
    {allow, _B4} = c(B3, 100, 30).

%% Under steady load slower than the consumption rate, requests are denied
%% but the denial never wastes tokens: the same request succeeds once the
%% next refill lands.
sustained_load_denies_and_rolls_forward_test() ->
    B0 = i2p_token_bucket:new(100, 100),
    {allow, B1} = c(B0, 100, 0),
    {allow, B2} = c(B1, 100, 1000),
    {allow, B3} = c(B2, 50, 1500),
    %% only 50 accrued since 1500: the 100 is denied and unchanged
    deny = c(B3, 100, 2000),
    %% the denied request rolls forward into the next full refill
    {allow, _B4} = c(B3, 100, 2500).

%% A denied consume is a no-op: tokens (and clock) are left exactly as if
%% the request had never been made.
deny_preserves_tokens_test() ->
    B0 = i2p_token_bucket:new(100, 100),
    {allow, B1} = c(B0, 50, 0),
    %% 60 available at t=100 (50 + 10); 100 is refused...
    deny = c(B1, 100, 100),
    %% ... and the very same bucket still approves the 60 it can afford
    {allow, _B2} = c(B1, 60, 100).

%% Clock moving backwards never loans tokens: refill is only ever forward.
backwards_clock_is_not_loaned_test() ->
    B0 = i2p_token_bucket:new(1, 1),
    {allow, B1} = c(B0, 1, 0),
    %% clock jumped back: nothing accrued
    deny = c(B1, 1, -500),
    %% 0.999 of a token is still shy
    deny = c(B1, 1, 999),
    {allow, _B2} = c(B1, 1, 1000).
