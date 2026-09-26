-module(i2p_peertest).

-moduledoc """
Pure signing and codec helpers for SSU2 PeerTest messages.

PeerTest messages 1 through 7 carry a signed request, response, or reachability
result. This module owns the exact signed byte strings, Ed25519 verification,
connection-ID derivation, and the `peertest` block representation consumed by
`m:i2p_ssu2`. See the [Peer Test](docs/protocol.md#peer-test) section of the
protocol reference for the wire layout and message flow.

## Usage

```erlang
Block = i2p_peertest:block(1, 0, 0, RouterHash, 2, Nonce, Timestamp, Port, Ip, Signature).
```
""".

-export([
    prologue/0,
    signed_data/8,
    sign/8,
    verify/9,
    block/10,
    dst_conn_id/1,
    src_conn_id/1,
    address_size/1,
    is_bob_reject/1,
    is_charlie_reject/1,
    is_reject/1,
    result/3
]).

-export_type([address_type/0, result/0, reject/0]).

-define(PROLOGUE, <<"PeerTestValidate">>).

-doc """
The peer-test signing prologue.

The 16-byte literal `"PeerTestValidate"` that prefixes every data block signed
by Alice (message 1) or Charlie (message 3), so Ed25519 signatures never
collide across I2P message classes.
""".
-spec prologue() -> <<_:128>>.
prologue() -> ?PROLOGUE.

-doc """
Build the exact bytes an SSU2 PeerTest signature covers.

Input: `BobHash` — the 32-byte introducer router hash; `CharlieHash` — the
32-byte tester hash for messages 3 and 4, or `undefined` for messages 1 and 2;
the SSU version (`2`); the Alice-chosen 4-byte test `Nonce`; the Unix
`Timestamp`; the endpoint address size (`asz`: 6 or 18); `Port` (0..65535); and
the Alice `Ip` bytes (4 or 16).
Output: the byte string
`prologue "PeerTestValidate" || BobHash || CharlieHash? || ver || nonce || ts ||
asz || port || ip`.
""".
-spec signed_data(
    binary(),
    undefined | binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    6 | 18,
    0..65535,
    binary()
) -> binary().
signed_data(BobHash, CharlieHash, Ver, Nonce, Ts, Asz, Port, Ip) ->
    HashPart =
        case CharlieHash of
            undefined -> <<>>;
            _ -> CharlieHash
        end,
    <<?PROLOGUE/binary, BobHash/binary, HashPart/binary, Ver:8, Nonce:32, Ts:32, Asz:8, Port:16,
        Ip/binary>>.

-doc """
Sign a peer-test request (Alice, message 1) or response (Charlie, message 3).

Input: `BobHash`; `CharlieHash` (`undefined` for message 1, Charlie's hash for
message 3); the SSU `Ver`; `Nonce`; `Timestamp`; `Port`; Alice's `Ip`; and the
`SignSeed` used to sign.
Output: a 64-byte Ed25519 signature.
""".
-spec sign(
    binary(),
    undefined | binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_seed()
) -> i2p_crypto:ed25519_signature().
sign(BobHash, CharlieHash, Ver, Nonce, Ts, Port, Ip, SignSeed) ->
    i2p_crypto:ed25519_sign(
        signed_data(BobHash, CharlieHash, Ver, Nonce, Ts, 2 + byte_size(Ip), Port, Ip),
        SignSeed
    ).

-doc """
Verify an SSU2 PeerTest signature.

Input: `BobHash`; `CharlieHash` (`undefined` unless verifying messages 3/4);
`Ver`; `Nonce`; `Timestamp`; `Port`; Alice's `Ip`; the `Signature`; and the
signer's Ed25519 `SignPub`.
Output: `true` when the signature verifies against `f:signed_data/8`, `false`
otherwise.
""".
-spec verify(
    binary(),
    undefined | binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    i2p_crypto:ed25519_signature(),
    i2p_crypto:ed25519_public_key()
) -> boolean().
verify(BobHash, CharlieHash, Ver, Nonce, Ts, Port, Ip, Signature, SignPub) ->
    i2p_crypto:ed25519_verify(
        signed_data(BobHash, CharlieHash, Ver, Nonce, Ts, 2 + byte_size(Ip), Port, Ip),
        Signature,
        SignPub
    ).

-doc """
Construct an SSU2 PeerTest payload `block()` (codec form) for any message.
""".
-spec block(
    1..7,
    byte(),
    byte(),
    binary(),
    byte(),
    non_neg_integer(),
    non_neg_integer(),
    0..65535,
    binary(),
    binary()
) -> i2p_ssu2:block().
block(MsgNum, Code, Flags, RouterHash, Ver, Nonce, Ts, Port, Ip, Sig) ->
    {peertest, MsgNum, Code, Flags, RouterHash, Ver, Nonce, Ts, Port, Ip, Sig}.

-doc """
The out-of-session destination connection ID derived from a test nonce.

For Charlie→Alice messages (5 and 7) the destination ID is
`(nonce << 32) | nonce`.
""".
-spec dst_conn_id(non_neg_integer()) -> non_neg_integer().
dst_conn_id(Nonce) ->
    (Nonce bsl 32) bor Nonce.

-doc """
The out-of-session source connection ID derived from a test nonce — the
bitwise inverse of the destination ID. Alice uses it as her source for the
Alice→Charlie message 6 (and as her expected destination of messages 5/7).
""".
-spec src_conn_id(non_neg_integer()) -> non_neg_integer().
src_conn_id(Nonce) ->
    (bnot dst_conn_id(Nonce)) band 16#FFFFFFFFFFFFFFFF.

-doc """
Endpoint address size for a peer-test: `6` for a 4-byte IPv4 address, `18` for
a 16-byte IPv6 address.
""".
-spec address_size(<<_:32>> | <<_:128>>) -> 6 | 18.
address_size(<<_:32>>) -> 6;
address_size(<<_:128>>) -> 18.

-doc """
`true` when `Code` is a Bob-side reject (1-5).
""".
-spec is_bob_reject(byte()) -> boolean().
is_bob_reject(Code) when Code >= 1, Code =< 5 -> true;
is_bob_reject(_) -> false.

-doc """
`true` when `Code` is a Charlie-side reject (64-70).
""".
-spec is_charlie_reject(byte()) -> boolean().
is_charlie_reject(Code) when Code >= 64, Code =< 70 -> true;
is_charlie_reject(_) -> false.

-doc """
`true` when `Code` is any reject (Bob 1-5, Charlie 64-70, or the catch-all 128).
""".
-spec is_reject(byte()) -> boolean().
is_reject(Code) ->
    is_bob_reject(Code) orelse is_charlie_reject(Code) orelse Code == 128.

-doc """
A tested address type: IPv4 or IPv6.
""".
-type address_type() :: ipv4 | ipv6.

-doc """
A peer-test reachability result, per the SSU2 spec result table.
""".
-type result() :: ok | firewalled | unknown.

-doc """
A Bob- or Charlie-side peer-test reject status code (see `f:is_reject/1`).
""".
-type reject() :: byte().

-doc """
Resolve the reachability result of a test from which of messages 4, 5 and 7
arrived.

Input: three booleans — whether the in-session message 4 (Bob's relay of
Charlie's response or a reject) and the out-of-session messages 5 and 7
(Charlie→Alice) were received. Waiting a few seconds after message 4 before
judging lets an absent message 5 still be detected after the settle window.
Output: `ok | firewalled | unknown` per the implemented result table.
""".
-spec result(boolean(), boolean(), boolean()) -> ok | firewalled | unknown.
result(false, false, false) -> unknown;
result(true, false, false) -> firewalled;
result(false, true, false) -> ok;
result(true, true, false) -> ok;
result(false, false, true) -> unknown;
result(true, false, true) -> firewalled;
result(false, true, true) -> ok;
result(true, true, true) -> ok.
