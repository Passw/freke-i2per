-module(i2p_token_bucket).

-moduledoc """
Pure token-bucket rate limiter used by `m:i2p_tunnel_srv` to pace transit
relay bandwidth and tunnel-build acceptance.

Tokens accrue continuously at a configured rate and are capped at a burst
capacity; each `f:consume/3` drains the requested token count when enough
have accrued. Time is passed in explicitly, so the limiter is a pure
function of its inputs and tests are fully deterministic.

## Usage

```erlang
%% Allow one build per second with a four-build burst
Bucket = i2p_token_bucket:new(1, 4),
{allow, Bucket1} = i2p_token_bucket:consume(Bucket, 1, NowMs),
deny = i2p_token_bucket:consume(Bucket1, 1, NowMs).
```
""".

-export([new/2, consume/3]).

-export_type([bucket/0, rate/0]).

-doc "Tokens accrued per second (builds/sec or bytes/sec).".
-type rate() :: pos_integer().

-doc """
The token bucket state. Opaque; created with `f:new/2` and threaded through
`f:consume/3` only.
""".
-opaque bucket() :: #{
    rate := rate(),
    capacity := pos_integer(),
    tokens := float(),
    last_refill_ms := integer()
}.

% %%%%% %%% Public API %%%%% %%

-doc """
Create a full bucket refilled at `RatePerSec` and bounded by `Capacity`.

Input: `RatePerSec` — tokens accrued per second; `Capacity` — the maximum
token stockpile (the burst size, also the number of tokens available at
creation). Output: a bucket already filled to `Capacity`, so the first
`Capacity` tokens' worth of traffic conforms immediately.
""".
-spec new(rate(), pos_integer()) -> bucket().
new(RatePerSec, Capacity) when RatePerSec > 0, Capacity > 0 ->
    #{
        rate => RatePerSec,
        capacity => Capacity,
        tokens => float(Capacity),
        last_refill_ms => 0
    }.

-doc """
Attempt to consume `Tokens` from the bucket as of wall-clock `NowMs`.

Input: `Bucket` — limiter state; `Tokens` — the amount to drain; `NowMs` —
the current time in milliseconds since epoch. Output: `{allow, Bucket1}`
when `Tokens` worth have accrued (the bucket's tokens are reduced and its
refill clock advanced to `NowMs`); `deny` when the bucket is short, in which
case no state changes — denied units are never lost, they roll forward into
the next refill. A `NowMs` before `last_refill_ms` (clock moved backwards)
refills nothing.
""".
-define(MS_PER_SEC, 1000).

-spec consume(bucket(), pos_integer(), integer()) -> {allow, bucket()} | deny.
consume(
    #{tokens := Tokens, rate := Rate, capacity := Capacity, last_refill_ms := Last} = Bucket,
    Needed,
    NowMs
) ->
    Elapsed = NowMs - Last,
    Accrued =
        case Elapsed > 0 of
            true -> Elapsed * Rate / ?MS_PER_SEC;
            false -> 0.0
        end,
    Refilled =
        case Tokens + Accrued =< Capacity of
            true -> Tokens + Accrued;
            false -> float(Capacity)
        end,
    case Refilled >= Needed of
        true ->
            Last1 =
                case Elapsed > 0 of
                    true -> NowMs;
                    false -> Last
                end,
            {allow, Bucket#{tokens => Refilled - Needed, last_refill_ms => Last1}};
        false ->
            deny
    end.
