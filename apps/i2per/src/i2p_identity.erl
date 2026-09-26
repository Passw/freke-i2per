-module(i2p_identity).

-moduledoc """
Persistent NTCP2 identity: load or generate the X25519 + Ed25519 keypairs,
IV, signing seed, and full identity bytes that make up a router's stable
identity.

The file is a versioned binary blob stored under the operator-configured
application `data_dir`. Once written it is never overwritten; deleting the file
and restarting generates a fresh
identity. The full identity bytes — including the random padding block — are
persisted so that the router hash (SHA-256 of the identity) stays stable
across restarts and RouterInfo rebuilds; it is the NetDb key and the NTCP2
message-1 AES key the network addresses us by.

When the `i2per` application env `floodfill` is `true`, the generated
RouterInfo includes the `f` capability flag, declaring this router as
floodfill-eligible on the network (see `m:i2p_floodfill`). The boot-time
`ntcp2_published` flag selects the address form: `true` publishes a reachable
NTCP2 endpoint; the default `false` publishes the firewalled cost-14 form.
""".

-export([
    ensure_identity/1,
    build_local/4,
    build_local/5,
    rebuild_router_info/1,
    rebuild_router_info/2,
    set_ssu2_introducers/2,
    ssu2_enabled/0,
    allow_private_host/0
]).

-export_type([identity_file/0]).

-doc "Decoded private router identity material loaded from `identity.bin`.".
-type identity_file() :: #{
    static_priv := i2p_crypto:x25519_private_key(),
    static_pub := i2p_crypto:x25519_public_key(),
    sign_pub := i2p_crypto:ed25519_public_key(),
    sign_seed := i2p_crypto:ed25519_seed(),
    iv := i2p_crypto:aes_iv(),
    identity := i2p_keys:identity()
}.

-define(FILE_VERSION, 2).

-doc """
Ensure an identity file exists in `Dir`.

Input: `Dir` — directory path for the identity file.
Output: `{ok, identity_file()}` with the loaded or freshly-generated key
material; `{error, Reason}` on filesystem failure.
""".
-spec ensure_identity(file:filename_all()) ->
    {ok, identity_file()} | {error, term()}.
ensure_identity(Dir) ->
    Path = filename:join(Dir, "identity.bin"),
    case file:read_file(Path) of
        {ok, Bin} ->
            case decode_identity(Bin) of
                {ok, Id} -> {ok, Id};
                {error, _} -> generate_and_write(Path)
            end;
        {error, enoent} ->
            ok = filelib:ensure_dir(Path),
            generate_and_write(Path);
        {error, _} = Err ->
            Err
    end.

-doc """
Build the `m:i2p_peer` local-keys map from identity file material and the
actual listener address.

Input: `Id` — `t:identity_file/0`; `Host` — listening IP (binary); `Port` —
bound TCP port; `Seed` — Ed25519 signing seed for RouterInfo generation.
Output: a fully populated local-keys map ready for `m:i2p_peer:start_link/2`.

When the `i2per` application env `ssu2_enabled` is `true`, the RouterInfo also
carries an SSU2 RouterAddress (derived intro key + `ssu2_port`) and the local
map carries the `intro_key` the SSU2 listener needs. Otherwise the RouterInfo
is NTCP2-only — we never advertise a transport we are not serving. When
`ntcp2_published` is `false`, the NTCP2 address is the non-published form and
is intentionally not returned by `i2p_router_info:ntcp2_connector/1`.
""".
-spec build_local(
    identity_file(),
    binary(),
    pos_integer(),
    i2p_crypto:ed25519_seed()
) -> i2p_peer:local_keys().
build_local(Id, Host, Port, Seed) ->
    build_local(Id, Host, Port, Seed, erlang:system_time(millisecond)).

-doc """
Build the `m:i2p_peer` local-keys map from identity file material and the
actual listener address, with an explicit publish timestamp.

Input: `Id` — `t:identity_file/0`; `Host` — listening IP (binary); `Port` —
bound TCP port; `Seed` — Ed25519 signing seed for RouterInfo generation;
`NowMs` — publish timestamp in ms since epoch for the built RouterInfo.
Output: a fully populated local-keys map ready for `m:i2p_peer:start_link/2`,
with a RouterInfo signed at `NowMs`.
""".
-spec build_local(
    identity_file(),
    binary(),
    pos_integer(),
    i2p_crypto:ed25519_seed(),
    non_neg_integer()
) -> i2p_peer:local_keys().
build_local(
    #{static_priv := Priv, identity := Identity, iv := IV},
    Host,
    Port,
    Seed,
    NowMs
) ->
    Pub = i2p_keys:public_key(Identity),
    NTCP2 =
        case ntcp2_published() of
            true -> i2p_router_info:ntcp2_address(Host, Port, Pub, IV);
            false -> i2p_router_info:ntcp2_nonpublished_address(address_family(Host), Pub)
        end,
    %% `router.version` is the I2P API compatibility marker, not the i2per
    %% application release number.
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => local_caps()
    },
    case ssu2_enabled() of
        true ->
            Intro = intro_key(Priv),
            SSU2Port = ssu2_port(Port),
            SSU2 = i2p_router_info:ssu2_address(Host, SSU2Port, Pub, Intro),
            RI = i2p_router_info:build(Identity, NowMs, [NTCP2, SSU2], Opts, Seed),
            #{
                static_priv => Priv,
                static_pub => Pub,
                hash => i2p_router_info:hash(RI),
                iv => IV,
                port => Port,
                sign_seed => Seed,
                sign_pub => i2p_keys:signing_key(Identity),
                intro_key => Intro,
                ssu2_addr => SSU2,
                ri => RI
            };
        false ->
            RI = i2p_router_info:build(Identity, NowMs, [NTCP2], Opts, Seed),
            #{
                static_priv => Priv,
                static_pub => Pub,
                hash => i2p_router_info:hash(RI),
                iv => IV,
                port => Port,
                sign_seed => Seed,
                sign_pub => i2p_keys:signing_key(Identity),
                ri => RI
            }
    end.

-doc """
Re-sign a router's RouterInfo with a fresh publish timestamp.

Input: `Local` — the `t:i2p_peer:local_keys/0` map built by
`f:build_local/4` (must carry `ri`, `sign_seed` and `iv`).
Output: an updated local map whose `ri` is a newly-signed RouterInfo over the
same identity, addresses and options but a fresh `published` timestamp. The
router `hash` is unchanged (it depends only on the identity), so the router's
NetDb key stays stable while the RouterInfo no longer ages out of peer netDbs.
""".
-spec rebuild_router_info(i2p_peer:local_keys()) -> i2p_peer:local_keys().
rebuild_router_info(Local) ->
    rebuild_router_info(Local, erlang:system_time(millisecond)).

-doc """
Re-sign a router's RouterInfo with an explicit fresh publish timestamp.

Input: `Local` — the `t:i2p_peer:local_keys/0` map built by
`f:build_local/4` (must carry `ri`, `sign_seed` and `iv`); `NowMs` — publish
timestamp in ms since epoch for the re-signed RouterInfo.
Output: an updated local map whose `ri` is a newly-signed RouterInfo over the
same identity, addresses and options but the passed `published` timestamp. The
router `hash` is unchanged (it depends only on the identity), so the router's
NetDb key stays stable while the RouterInfo no longer ages out of peer netDbs.
""".
-spec rebuild_router_info(i2p_peer:local_keys(), non_neg_integer()) -> i2p_peer:local_keys().
rebuild_router_info(Local, NowMs) ->
    #{ri := RI, sign_seed := Seed} = Local,
    Identity = i2p_router_info:identity(RI),
    Addresses = i2p_router_info:addresses(RI),
    Options = i2p_router_info:options(RI),
    Fresh = i2p_router_info:build(Identity, NowMs, Addresses, Options, Seed),
    Local#{ri => Fresh}.

-doc """
Publish this router as firewalled by swapping its published SSU2 address for a
non-published introducer address, or restore the published address.

Input: `Local` — the `t:i2p_peer:local_keys/0` map built by
`f:build_local/4` (must carry `ri`, `sign_seed`, `static_pub` and
`intro_key`; the originally published SSU2 address is kept under `ssu2_addr`
so it can be restored); `Introducers` — up to
`t:i2p_router_info:introducer/0` entries being relied on, or `[]` to restore
the originally published SSU2 address and publish as reachable again.
Output: an updated local map whose `ri` is re-signed over the new address
list with a fresh publish timestamp. The router `hash` is unchanged.
""".
-spec set_ssu2_introducers(i2p_peer:local_keys(), [i2p_router_info:introducer()]) ->
    i2p_peer:local_keys().
set_ssu2_introducers(Local = #{intro_key := Intro, static_pub := Pub}, Introducers) when
    is_list(Introducers)
->
    #{ri := RI, sign_seed := Seed} = Local,
    Identity = i2p_router_info:identity(RI),
    Addresses = i2p_router_info:addresses(RI),
    Options = i2p_router_info:options(RI),
    Published = maps:get(ssu2_addr, Local, undefined),
    NewAddresses = swapped_addresses(Addresses, Published, Introducers, Pub, Intro),
    NowMs = erlang:system_time(millisecond),
    Fresh = i2p_router_info:build(Identity, NowMs, NewAddresses, Options, Seed),
    Local#{ri => Fresh};
set_ssu2_introducers(Local, _Introducers) ->
    %% No SSU2 material (booted without SSU2): nothing to swap.
    Local.

%% Replace the first SSU2-style address in the list (there is exactly one for
%% a local router); keep every other address untouched.
swapped_addresses(Addresses, Published, [], _Pub, _Intro) ->
    %% Restore: put the published SSU2 address back in place of the current
    %% (possibly non-published) one. Without a stored published address the
    %% list is left as-is.
    case Published of
        undefined -> Addresses;
        _ -> replace_first_ssu2(Addresses, Published)
    end;
swapped_addresses(Addresses, Published, Introducers, Pub, Intro) ->
    case first_ssu2(Addresses) of
        undefined ->
            Addresses;
        Current ->
            NewAddr =
                i2p_router_info:ssu2_introducer_address(
                    family_host(Published, Current), Pub, Intro, Introducers
                ),
            replace_first_ssu2(Addresses, NewAddr)
    end.

first_ssu2([Addr | Rest]) ->
    case maps:get(transport, Addr) of
        <<"SSU", _/binary>> -> Addr;
        _ -> first_ssu2(Rest)
    end;
first_ssu2([]) ->
    undefined.

replace_first_ssu2([Addr | Rest], NewAddr) ->
    case maps:get(transport, Addr) of
        <<"SSU", _/binary>> -> [NewAddr | Rest];
        _ -> [Addr | replace_first_ssu2(Rest, NewAddr)]
    end;
replace_first_ssu2([], _NewAddr) ->
    [].

%% The family placeholder for the non-published address: prefer the host of
%% the originally published SSU2 address (our real family), falling back to
%% the current address's host, then the IPv4 unspecified address.
family_host(Published, _Current) when Published =/= undefined ->
    maps:get(host, maps:get(options, Published), <<"0.0.0.0">>);
family_host(undefined, Current) ->
    maps:get(host, maps:get(options, Current), <<"0.0.0.0">>).

%%%%%%%% %%% Internal %%%%%%%

%% Router-level `caps` value: bandwidth class + reachability + floodfill.
%% `R` (reachable) only when NTCP2 is published and the operator did not opt
%% into a private/local host. The default bandwidth class is `L` (overridable
%% via app env `caps_bandwidth`); `f` is appended for a floodfill.
local_caps() ->
    Bandwidth = application:get_env(i2per, caps_bandwidth, $L),
    Reachable = ntcp2_published() andalso not allow_private_host(),
    Floodfill = i2p_floodfill:is_floodfill(),
    i2p_router_info:caps_string(Bandwidth, Reachable, Floodfill).

ntcp2_published() ->
    case application:get_env(i2per, ntcp2_published) of
        {ok, false} -> false;
        _ -> true
    end.

address_family(Host) ->
    case inet:parse_ipv4_address(binary_to_list(Host)) of
        {ok, _} -> ipv4;
        {error, _} -> ipv6
    end.

allow_private_host() ->
    case application:get_env(i2per, allow_private_host) of
        {ok, true} -> true;
        _ -> false
    end.

%% SSU2 introduction key: deterministically derived from the router's static
%% X25519 private key so it is stable across restarts without a file-format
%% bump, yet secret (only the holder of the static key can derive it).
intro_key(StaticPriv) ->
    crypto:hash(sha256, <<StaticPriv/binary, "i2p-ssu2-intro">>).

-doc """
Whether the SSU2 transport is wired into this router.

Mirrors app env `i2per` -> `ssu2_enabled` (default `false`). When `true` the
RouterInfo carries an SSU2 address and the boot listener is bound; `m:i2per_sup`
consults this to decide whether to bring up SSU2 at boot.
""".
-spec ssu2_enabled() -> boolean().
ssu2_enabled() ->
    case application:get_env(i2per, ssu2_enabled) of
        {ok, true} -> true;
        _ -> false
    end.

%% SSU2 UDP port: defaults to the configured TCP port (like real routers,
%% which serve both transports on the same port number).
ssu2_port(TcpPort) ->
    case application:get_env(i2per, ssu2_port) of
        {ok, P} when is_integer(P), P >= 1, P =< 65535 -> P;
        _ -> TcpPort
    end.

generate_and_write(Path) ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, SignSeed} = i2p_crypto:ed25519_keygen(),
    IV = crypto:strong_rand_bytes(16),
    Id = #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        sign_pub => SignPub,
        sign_seed => SignSeed,
        iv => IV,
        identity => i2p_keys:from_keys(StaticPub, SignPub)
    },
    Bin = encode_identity(Id),
    case file:write_file(Path, Bin) of
        ok -> {ok, Id};
        {error, _} = Err -> Err
    end.

encode_identity(#{
    static_priv := SPriv,
    sign_seed := SigSeed,
    iv := IV,
    identity := Identity
}) ->
    IdentityBin = i2p_keys:to_binary(Identity),
    <<?FILE_VERSION:8, (byte_size(IdentityBin)):16, IdentityBin/binary, SPriv/binary,
        SigSeed/binary, IV/binary>>.

decode_identity(
    <<?FILE_VERSION:8, IdLen:16, IdentityBin:IdLen/binary, SPriv:32/binary, SigSeed:32/binary,
        IV:16/binary>>
) ->
    case i2p_keys:parse(IdentityBin) of
        {ok, Identity} ->
            {ok, #{
                static_priv => SPriv,
                static_pub => i2p_keys:public_key(Identity),
                sign_pub => i2p_keys:signing_key(Identity),
                sign_seed => SigSeed,
                iv => IV,
                identity => Identity
            }};
        {error, _} ->
            {error, bad_identity_file}
    end;
decode_identity(_) ->
    {error, bad_identity_file}.
