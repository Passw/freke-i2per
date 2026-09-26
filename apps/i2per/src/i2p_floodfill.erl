-module(i2p_floodfill).

-moduledoc """
Floodfill election, store replication, and DHT observability.

This is a pure library module — no process, no state. It answers questions
about whether this router is a floodfill, which peers should receive a
replicated store, and how to build the forwarding messages. The actual
sending is done by `m:i2p_peer` via `f:m:i2p_peer:send_when_ready/2`.

## Floodfill election

A router declares itself a floodfill by including `f` in its RouterInfo caps
option. This module reads the `i2per` application env `floodfill` flag (boolean,
default `false`) to decide. When enabled, `m:i2p_identity:build_local/4`
includes the `f` cap in our RouterInfo, and this module returns `true`.

## Store replication

When a floodfill receives a DatabaseStore with a nonzero reply token (an
announcement from another router), it stores locally and then forwards the entry
to the three closest eligible floodfills in the NetDb — excluding itself and
the originator — with `reply_token = 0` (no DeliveryStatus expected from the
replication targets). This is i2pd's `NetDb::Store` replication path.

The `f:replication_outbox/4` function computes which peers should receive the
forwarded store and builds the corresponding I2NP messages, without sending
them. The caller (`m:i2p_peer`) iterates the outbox and sends each message via
`f:m:i2p_peer:send_when_ready/2`.

## Usage

```erlang
%% Check if this router is a floodfill.
i2p_floodfill:is_floodfill().

%% Compute the replication outbox for a RouterInfo store.
OurHash = i2p_router_info:hash(OurRI),
Outbox = i2p_floodfill:replication_outbox(0, Key, RIData, OurHash, SenderHash),
lists:foreach(fun({Target, Msg}) ->
    i2p_peer:send_when_ready(Target, Msg)
end, Outbox).
```
""".

-export([
    is_floodfill/0,
    replication_outbox/5
]).

-export_type([]).

-doc """
Whether this router is configured as a floodfill.

Reads the `i2per` application env `floodfill` flag (boolean, default `false`).

Output: `true` when floodfill mode is enabled, `false` otherwise.
""".
-spec is_floodfill() -> boolean().
is_floodfill() ->
    case application:get_env(i2per, floodfill) of
        {ok, true} -> true;
        _ -> false
    end.

-doc """
Compute the replication outbox for an incoming DatabaseStore.

Given a stored entry, returns a list of `{TargetHash, I2NPMessage}` tuples
representing the DatabaseStore messages to forward to the closest eligible
floodfills. Each message has `reply_token = 0` and `reply = undefined` (no
DeliveryStatus expected from replication targets).

Input: `StoreType` — `0` for RouterInfo, `1` for LeaseSet; `Key` — the 32-byte
hash of the stored object; `Data` — the raw payload bytes (`f:router_info_data/1`
output for a RouterInfo, raw content for a LeaseSet); `OurHash` — our router
hash (to exclude from targets); `SenderHash` — the originator's hash (to
exclude from targets).

Output: a list of `{TargetHash, I2NPMessage}` tuples, typically 0–3 entries.
Empty when no eligible floodfills are reachable or when the caller is not a
floodfill.
""".
-spec replication_outbox(byte(), i2p_crypto:hash(), binary(), i2p_crypto:hash(), i2p_crypto:hash()) ->
    [{i2p_crypto:hash(), i2p_i2np:i2np_message()}].
replication_outbox(StoreType, Key, Data, OurHash, SenderHash) ->
    %% Stays a case: the scrutinee is an is_floodfill() call, not
    %% guard-expressible.
    case is_floodfill() of
        false ->
            [];
        true ->
            Excluded = [OurHash, SenderHash],
            Targets = i2p_netdb_srv:closest_floodfills(Key, 3, Excluded),
            [{T, i2p_i2np:db_store(Key, StoreType, 0, undefined, Data)} || T <- Targets]
    end.
