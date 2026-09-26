%% SSU2 introducer relay tests. The suite covers relay-tag issuance, rejection
%% of an unknown tag, and the complete 15/16 plus 7/8/9 introducer flow. The
%% code under test is `m:i2p_relay_coord`, the listener-owned tag registry,
%% and relay-block plumbing in `m:i2p_ssu2_conn`.
%%
%% Each case owns its process, app lifecycle, and registry rows. Every wait
%% drains non-matching mail through `m:i2p_ct_helpers:wait_msg/2`. Relay
%% blocks are ack-eliciting and use the same bounded receive windows as the
%% peer-test suite.

-module(i2p_ssu2_relay_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    relay_tag_request_handshake/1,
    relay_request_unknown_tag_rejected/1,
    indirect_dial_through_introducer/1
]).

-define(APP, i2per).
-define(DATA_WINDOW, 25000).
-define(RELAY_WINDOW, 30000).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        relay_tag_request_handshake,
        relay_request_unknown_tag_rejected,
        indirect_dial_through_introducer
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: the full app is started so the SSU2 session/listener
%% tree and the relay-tag registry come up, and stopped at the end so neither
%% a session nor a registry row leaks into the next testcase.
%% ---------------------------------------------------------------------------

init_per_testcase(Case, Config) ->
    i2p_ct_helpers:start_ssu2_trace(),
    start_app(
        Config,
        case Case of
            indirect_dial_through_introducer -> 40000;
            _ -> 30000
        end
    ).

start_app(Config, Timetrap) ->
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, Timetrap} | Config].

end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

%% ---------------------------------------------------------------------------
%% Relay-tag handshake (blocks 15/16)
%% ---------------------------------------------------------------------------

%% Bob answers an in-session relay-tag request with a fresh nonzero tag (block
%% 16) and records it against the requesting session — the Bob-side session,
%% not the peer's own dial — in the listener-owned registry, with a future
%% expiry. The same tag then authorizes relay requests for that session.
relay_tag_request_handshake(_Config) ->
    {BobLocal, _} = bob_local(),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        {PeerPid, _Listener, _PeerLocal} = dial_peer(Coord, BobLocal),
        Tag = request_tag(PeerPid),
        true = Tag > 0,

        TaggedSess = i2p_relay_coord:tagged_sess(Coord),
        [{Tag, RegPid, Expires}] = ets:lookup(i2p_ssu2_relay_tags, Tag),
        %% The registry maps the tag to the Bob-side session that holds it…
        true = RegPid =:= TaggedSess,
        true = is_process_alive(RegPid),
        true = RegPid =/= PeerPid,
        %% …with a usable lifetime.
        true = Expires > erlang:system_time(second)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% ---------------------------------------------------------------------------
%% Rejected relay requests
%% ---------------------------------------------------------------------------

%% A RelayRequest (block 7) targeting a tag no session holds is answered with
%% Bob's "relay tag not found" reject (code 5) — signed by Bob, csz 0, echoing
%% the request nonce — and nothing is served (the registry stays empty).
relay_request_unknown_tag_rejected(_Config) ->
    {BobLocal, _} = bob_local(),
    BobHash = maps:get(hash, BobLocal),
    BobSignPub = maps:get(sign_pub, BobLocal),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        {ReqPid, ReqListener, ReqLocal} = dial_peer(Coord, BobLocal),
        ReqPort = i2p_ssu2_listener:port(ReqListener),
        ReqIp = <<127, 0, 0, 1>>,
        UnknownTag = 16#0BADC0DE,
        %% Any well-formed request context works here; Bob refuses the tag
        %% before a target hash matters.
        UnknownTarget = crypto:strong_rand_bytes(32),
        Nonce = 16#DEADBEEF,
        Ts = erlang:system_time(second),
        ReqSig = i2p_relay:sign_request(
            BobHash,
            UnknownTarget,
            2,
            Nonce,
            UnknownTag,
            Ts,
            ReqPort,
            ReqIp,
            maps:get(sign_seed, ReqLocal)
        ),
        ok = i2p_ssu2_conn:send_relay(
            ReqPid, i2p_relay:request_block(2, Nonce, UnknownTag, Ts, ReqPort, ReqIp, ReqSig)
        ),

        ok = i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_data, P, Blocks}) when P =:= ReqPid ->
                    case lists:keyfind(relay_response, 1, Blocks) of
                        {relay_response, 0, 5, Nonce, RejTs, 2, 0, <<>>, BobSig, undefined} ->
                            true =
                                i2p_relay:verify_response(
                                    BobHash, 2, Nonce, RejTs, 0, <<>>, BobSig, BobSignPub
                                ),
                            {true, ok};
                        Other ->
                            erlang:error({unexpected_reject, Other})
                    end;
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ),

        [] = ets:tab2list(i2p_ssu2_relay_tags)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% ---------------------------------------------------------------------------
%% Indirect dial through the introducer (blocks 15/16 + 7/8/9)
%% ---------------------------------------------------------------------------

%% The end-to-end loopback: the tagged peer (T) earns a tag from Bob; the
%% requester (A) dials Bob, sends a signed RelayRequest, and T — reached only
%% through the introducer — verifies A's signature against the RouterInfo Bob
%% forwarded, replies with a signed accept in block 8, and A then dials T
%% directly. The direct session succeeding is the acceptance proof: no route
%% from A to T existed before the introducer relayed.
indirect_dial_through_introducer(_Config) ->
    {BobLocal, _} = bob_local(),
    BobHash = maps:get(hash, BobLocal),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        %% -- Tagged peer (T): dials Bob and requests a relay tag.
        {TPid, TListener, TLocal} = dial_peer(Coord, BobLocal),
        Tag = request_tag(TPid),
        true = Tag > 0,
        TRI = maps:get(ri, TLocal),
        THash = i2p_router_info:hash(TRI),
        TPort = i2p_ssu2_listener:port(TListener),
        TIp = <<127, 0, 0, 1>>,

        %% -- Requester (A): dials Bob too. She knows T's RouterInfo only via
        %% the harness's netDb stand-in (the RI map); there is no direct route.
        {APid, AListener, ALocal} = dial_peer(Coord, BobLocal),
        ARIBlock = maps:get(ri_binary, ALocal),
        AHash = i2p_router_info:hash(maps:get(ri, ALocal)),
        ASignPub = maps:get(sign_pub, ALocal),
        ASeed = maps:get(sign_seed, ALocal),
        AIPort = i2p_ssu2_listener:port(AListener),
        AIp = <<127, 0, 0, 1>>,

        Nonce = 16#CAFEBABE,
        Ts = erlang:system_time(second),
        ReqSig = i2p_relay:sign_request(BobHash, THash, 2, Nonce, Tag, Ts, AIPort, AIp, ASeed),
        ok = i2p_ssu2_conn:send_relay(
            APid, i2p_relay:request_block(2, Nonce, Tag, Ts, AIPort, AIp, ReqSig)
        ),

        %% -- T receives A's RouterInfo (forwarded by Bob, no in-session
        %% RouterInfo block was needed) and the RelayIntro, and verifies A's
        %% signature chain end-to-end against her published signing key.
        ok = wait_request_relayed(
            TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, false, false
        ),

        %% -- T accepts: a signed block 8 carrying T's reachable endpoint.
        RespTs = erlang:system_time(second),
        RespSig = i2p_relay:sign_response(
            BobHash, 2, Nonce, RespTs, TPort, TIp, maps:get(sign_seed, TLocal)
        ),
        ok = i2p_ssu2_conn:send_relay(
            TPid, i2p_relay:response_block(0, 2, Nonce, RespTs, TPort, TIp, RespSig, undefined)
        ),

        %% -- A receives the relayed block 8 and validates T's signature; the
        %% endpoint it carries matches T's advertised SSU2 address.
        {ok, TOpts} = i2p_router_info:ssu2_address_options(TRI),
        true = maps:get(port, TOpts) =:= TPort,
        ok = wait_relay_response(APid, BobHash, Nonce, maps:get(sign_pub, TLocal), TPort, TIp),

        %% -- The indirect dial: A dials T at her advertised address. No
        %% session between A and T had ever existed up to now.
        {ok, DirectPid, _Keys} = i2p_ssu2_conn:connect(ALocal, TOpts, ARIBlock, AListener),
        unlink(DirectPid)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

%% Dial the coordinator's listener from a fresh peer, returning its session
%% pid, listener and full local map (hash/RI carried, so the caller can
%% verify signatures and recover the peer's advertised address).
dial_peer(Coord, BobLocal) ->
    {PeerListener, _PeerPort, PeerLocal} = listen_full_local(<<"127.0.0.1">>),
    PeerRIBlock = maps:get(ri_binary, PeerLocal),
    BobPort = i2p_relay_coord:port(Coord),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => BobPort,
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },
    {ok, PeerPid, _Keys} = i2p_ssu2_conn:connect(PeerLocal, RemoteOpts, PeerRIBlock, PeerListener),
    unlink(PeerPid),
    {PeerPid, PeerListener, PeerLocal}.

%% Ask the introducer for a relay tag (block 15) and await the RelayTag reply
%% (block 16).
request_tag(PeerPid) ->
    ok = i2p_ssu2_conn:send_relay(PeerPid, relay_tag_request),
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= PeerPid ->
                case lists:keyfind(relay_tag, 1, Blocks) of
                    {relay_tag, Tag} -> {true, Tag};
                    false -> false
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% Accumulate the two legs T must receive from the introducer — A's
%% forwarded RouterInfo and the RelayIntro (block 9) — which land as separate
%% Data messages in either order. The intro leg also verifies A's request
%% signature against the key her RouterInfo publishes, closing the
%% sign/forward/verify circle.
wait_request_relayed(TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, SeenRI, SeenIntro) ->
    Deadline = erlang:monotonic_time(millisecond) + ?RELAY_WINDOW,
    wait_request_relayed(
        TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, SeenRI, SeenIntro, Deadline
    ).

wait_request_relayed(_TPid, _AH, _ASP, _BH, _TH, _Nonce, _Tag, _Ts, true, true, _Deadline) ->
    ok;
wait_request_relayed(
    TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, SeenRI, SeenIntro, Deadline
) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            erlang:error({no_relay_request_forwarded, SeenRI, SeenIntro});
        false ->
            receive
                {ssu2_data, TPid, Blocks} ->
                    SeenRI1 = SeenRI orelse has_requester_ri(Blocks, AHash, ASignPub),
                    SeenIntro1 =
                        SeenIntro orelse
                            has_relay_intro(
                                Blocks, BobHash, THash, Nonce, Tag, Ts, ASignPub
                            ),
                    wait_request_relayed(
                        TPid,
                        AHash,
                        ASignPub,
                        BobHash,
                        THash,
                        Nonce,
                        Tag,
                        Ts,
                        SeenRI1,
                        SeenIntro1,
                        Deadline
                    );
                _ ->
                    wait_request_relayed(
                        TPid,
                        AHash,
                        ASignPub,
                        BobHash,
                        THash,
                        Nonce,
                        Tag,
                        Ts,
                        SeenRI,
                        SeenIntro,
                        Deadline
                    )
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                erlang:error({no_relay_request_forwarded, SeenRI, SeenIntro})
            end
    end.

%% The forwarded RouterInfo is A's own: same hash, same published signing key.
has_requester_ri(Blocks, AHash, ASignPub) ->
    case lists:keyfind(router_info, 1, Blocks) of
        {router_info, 0, RIData} ->
            {ok, RI} = i2p_router_info:decode(RIData),
            AHash = i2p_router_info:hash(RI),
            ASignPub = i2p_keys:signing_key(i2p_router_info:identity(RI)),
            true;
        _ ->
            false
    end.

%% The RelayIntro echoes the request (same nonce/tag/timestamp/endpoint) and
%% carries A's request signature, which verifies against A's signing key.
has_relay_intro(Blocks, BobHash, THash, Nonce, Tag, Ts, ASignPub) ->
    case lists:keyfind(relay_intro, 1, Blocks) of
        {relay_intro, 0, _AHash, Nonce, Tag, Ts, 2, Port, Ip, Sig} ->
            true = i2p_relay:verify_request(
                BobHash, THash, 2, Nonce, Tag, Ts, Port, Ip, Sig, ASignPub
            ),
            true;
        _ ->
            false
    end.

%% The relayed RelayResponse (block 8): T's accept, carrying T's reachable
%% endpoint and signed by T's key.
wait_relay_response(APid, BobHash, Nonce, TSignPub, TPort, TIp) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= APid ->
                case lists:keyfind(relay_response, 1, Blocks) of
                    {relay_response, 0, 0, Nonce, ResTs, 2, TPort, TIp, Sig, undefined} ->
                        true =
                            i2p_relay:verify_response(
                                BobHash, 2, Nonce, ResTs, TPort, TIp, Sig, TSignPub
                            ),
                        {true, ok};
                    Other ->
                        erlang:error({unexpected_relay_response, Other})
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% ---------------------------------------------------------------------------
%% Fixtures
%% ---------------------------------------------------------------------------

%% A fresh listener-bound peer: static/signing keys, a RouterInfo whose
%% advertised port equals the listener's real port (needed for the final
%% direct dial), plus the full local map (hash, ri, ri_binary).
listen_full_local(Host) ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Base =
        #{
            static_priv => Priv,
            static_pub => Pub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub
        },
    {ok, Listener} = i2p_ssu2_listener:listen(Host, 0, Base, self()),
    Port = i2p_ssu2_listener:port(Listener),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(Host, Port, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    Local =
        Base#{
            hash => i2p_router_info:hash(RI),
            ri => RI,
            ri_binary => maps:get(binary, RI)
        },
    {Listener, Port, Local}.

%% Bob's full local map with hash and RI, as `peer_local` provides in the
%% peer-test suite.
bob_local() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19152, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    Local =
        #{
            static_priv => Priv,
            static_pub => Pub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub,
            hash => i2p_router_info:hash(RI),
            ri => RI
        },
    {Local, maps:get(binary, RI)}.
