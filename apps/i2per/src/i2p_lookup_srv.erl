-module(i2p_lookup_srv).

-moduledoc """
Remote NetDb lookup orchestrator: answers "fetch this LeaseSet /
RouterInfo from the network" by querying floodfills through our own tunnels
and correlating the tunnel-delivered replies.

Flow for one pending key:

1. The local NetDb is checked first; a hit replies immediately.
2. Otherwise up to three floodfill candidates closest to the key are queried
   in turn. Each query is a DatabaseLookup carrying our inbound-tunnel reply
   address (`f:i2p_i2np:db_lookup_via_tunnel/5`) delivered `{router, FF}`
   through an outbound tunnel (`f:i2p_tunnel_srv:send_via_outbound/3`).
3. Replies arrive inside that inbound tunnel and are routed here by
   `m:i2p_tunnel_srv`: a DatabaseStore resolves the waiters, a
   DatabaseSearchReply contributes its closer-peer list to the chase queue.
4. When floodfill candidates run out, queued chase peers (routers the
   responders think are close to the key) are queried directly; after
   `?MAX_ATTEMPTS` sends or the overall deadline the lookup fails.

Callers block in `f:find_ls/1` / `f:find_ri/1` until resolution or failure.
SAM STREAM CONNECT uses this to resolve uncached destinations.
""".

-behaviour(gen_server).

-export([
    start_link/1,
    find_ls/1,
    find_ri/1,
    stop/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(ATTEMPT_TIMEOUT_MS, 4000).
-define(OVERALL_DEADLINE_MS, 18_000).
-define(MAX_ATTEMPTS, 5).
-define(CANDIDATES_PER_ROUND, 3).

-type kind() :: lease | router.

-doc """
A pending lookup: which kind of record, who waits, what was tried, which
closer peers to chase, and the retry/deadline bookkeeping.
""".
-type pending() :: #{
    kind := kind(),
    callers := [{gen_server:from(), pid(), reference()}],
    tried := [i2p_crypto:hash()],
    chase := [i2p_crypto:hash()],
    attempts := non_neg_integer(),
    deadline := integer(),
    timer := undefined | reference()
}.

-opaque state() :: #{pending := #{i2p_crypto:hash() => pending()}, our_hash := i2p_crypto:hash()}.
-export_type([state/0]).

-doc """
Start the orchestrator.

Input: `OurHash` — this router's identity hash (the DatabaseLookup sender).
""".
-spec start_link(i2p_crypto:hash()) -> {ok, pid()} | {error, term()}.
start_link(OurHash) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [OurHash], []).

-doc """
Fetch a LeaseSet from the network, blocking until it resolves.

Input: `Key` — the destination hash.
Output: `{ok, LeaseSet}` once a responder's store lands (it is stored into
the NetDb by the tunnel dispatch), `{error, not_found}` when attempts are
exhausted, or `{error, not_found}` when the service is not running. A locally
cached LeaseSet replies immediately.
""".
-spec find_ls(i2p_crypto:hash()) -> {ok, i2p_leaset:lease_set()} | {error, not_found}.
find_ls(Key) ->
    lookup(Key, lease).

-doc "As `f:find_ls/1` but for a RouterInfo.".
-spec find_ri(i2p_crypto:hash()) -> {ok, i2p_router_info:router_info()} | {error, not_found}.
find_ri(Key) ->
    lookup(Key, router).

-doc "Stop the orchestrator.".
-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

%% lookup/2 — the synchronous front door shared by find_ls/find_ri.
lookup(Key, Kind) ->
    case whereis(?MODULE) of
        undefined ->
            {error, not_found};
        _Pid ->
            gen_server:call(?MODULE, {find, Key, Kind}, ?OVERALL_DEADLINE_MS + 2000)
    end.

-spec init([i2p_crypto:hash()]) -> {ok, state()}.
init([OurHash]) ->
    {ok, #{pending => #{}, our_hash => OurHash}}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {noreply, state()} | {reply, term(), state()}.
handle_call({find, Key, Kind}, From, State = #{pending := Pending}) ->
    case cached(Kind, Key) of
        {ok, _Result} = Hit ->
            {reply, Hit, State};
        error ->
            _ =
                case maps:is_key(Key, Pending) of
                    false ->
                        %% First waiter arms the machinery.
                        self() ! {next_attempt, Key};
                    true ->
                        ok
                end,
            CallerPid = element(1, From),
            MRef = erlang:monitor(process, CallerPid),
            Entry0 =
                case maps:find(Key, Pending) of
                    {ok, P} ->
                        P;
                    error ->
                        #{
                            kind => Kind,
                            callers => [],
                            tried => [],
                            chase => [],
                            attempts => 0,
                            deadline =>
                                erlang:monotonic_time(millisecond) + ?OVERALL_DEADLINE_MS,
                            timer => undefined
                        }
                end,
            Entry = Entry0#{callers := [{From, CallerPid, MRef} | maps:get(callers, Entry0)]},
            {noreply, State#{pending := maps:put(Key, Entry, Pending)}}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({next_attempt, Key}, State) ->
    {noreply, attempt(Key, State)};
handle_info({db_stored, Key, Kind}, State) ->
    {noreply, resolve_stored(Key, Kind, State)};
handle_info({search_reply, Key, Peers}, State) ->
    {noreply, chase(Key, Peers, State)};
handle_info({attempt_timeout, Key, Ref}, State) ->
    %% Stale-timeout guard: only advance when the fired timer is still the
    %% pending one (a search reply may already have moved the lookup on).
    {noreply, attempt_timeout(Key, Ref, State)};
handle_info({'DOWN', MRef, process, _Pid, _Reason}, State) ->
    {noreply, drop_caller(MRef, State)};
handle_info(_Info, State) ->
    {noreply, State}.

%%%%%%% %%% Internal %%%%%%%

cached(lease, Key) ->
    case i2p_netdb_srv:find_ls(Key) of
        {ok, LS} -> {ok, LS};
        not_found -> error
    end;
cached(router, Key) ->
    case i2p_netdb_srv:find(Key) of
        {ok, RI} -> {ok, RI};
        not_found -> error
    end.

%% attempt_timeout/3 — advance only when the fired timer is still current.
attempt_timeout(Key, Ref, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        {ok, #{timer := Ref}} -> attempt(Key, State);
        _Other -> State
    end.

%% attempt/2 — send the next DatabaseLookup for Key, or give up.
attempt(Key, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            DeadlineHit = erlang:monotonic_time(millisecond) >= maps:get(deadline, P),
            Exhausted = maps:get(attempts, P) >= ?MAX_ATTEMPTS,
            case DeadlineHit orelse Exhausted of
                true ->
                    fail(Key, State);
                false ->
                    case next_target(Key, P) of
                        {ok, Hash, P1} ->
                            Timer = arm_timer(Key),
                            P2 = P1#{attempts := maps:get(attempts, P1) + 1, timer := Timer},
                            _ = send_lookup(P2, Key, Hash, maps:get(our_hash, State)),
                            State#{pending := maps:put(Key, P2, Pending)};
                        error ->
                            fail(Key, State)
                    end
            end
    end.

%% next_target/2 — the next untried floodfill candidate, else a chase peer.
next_target(Key, P) ->
    Tried = maps:get(tried, P),
    Fresh = i2p_netdb_srv:closest_floodfills(Key, ?CANDIDATES_PER_ROUND, Tried) -- Tried,
    case Fresh of
        [Hash | Rest] ->
            {ok, Hash, P#{tried := [Hash | Tried], chase := maps:get(chase, P) ++ Rest}};
        [] ->
            case maps:get(chase, P) -- Tried of
                [Hash | Rest] ->
                    {ok, Hash, P#{tried := [Hash | Tried], chase := Rest}};
                [] ->
                    error
            end
    end.

%% send_lookup/3 — one DatabaseLookup toward Target through the tunnels.
%% Lookups prefer the short exploratory pool so client towers stay free
%% for streams; when no tunnel is active the timer simply re-arms via
%% attempt/2 until the deadline fails the lookup.
send_lookup(P, Key, Target, OurHash) ->
    case i2p_tunnel_srv:pick_lookup_inbound() of
        {ok, RecvTid, _InEntry} ->
            Flag = flag_for(maps:get(kind, P)),
            Msg = i2p_i2np:db_lookup_via_tunnel(Key, OurHash, Flag, RecvTid, []),
            StdBin = std_binary(Msg),
            case i2p_tunnel_srv:pick_lookup_outbound() of
                {ok, OutTid, _OutEntry} ->
                    i2p_tunnel_srv:send_via_outbound(OutTid, {router, Target}, StdBin);
                error ->
                    error
            end;
        error ->
            error
    end.

%% std_binary/1 — a builder-produced message map to wire form; builders stamp
%% `expiration` in epoch seconds while the standard header wants a relative
%% lifetime in milliseconds.
std_binary(#{type := Type, msg_id := MsgID, body := Body}) ->
    i2p_i2np:encode_std(#{
        type => Type,
        msg_id => MsgID,
        expiration_ms => 60_000,
        body => Body
    }).

flag_for(lease) -> i2p_i2np:lookup_type_leaseset();
flag_for(router) -> i2p_i2np:lookup_type_routerinfo().

arm_timer(Key) ->
    Ref = erlang:make_ref(),
    erlang:send_after(?ATTEMPT_TIMEOUT_MS, self(), {attempt_timeout, Key, Ref}),
    Ref.

%% resolve_stored/3 — a DatabaseStore landed for a pending key.
resolve_stored(Key, _Kind, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            cancel_timer(P),
            Reply =
                case cached(maps:get(kind, P), Key) of
                    {ok, _R} = Hit -> Hit;
                    error -> {error, not_found}
                end,
            reply_all(maps:get(callers, P), Reply),
            State#{pending := maps:remove(Key, Pending)}
    end.

%% chase/3 — a search reply contributed closer routers to try.
chase(Key, Peers, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            cancel_timer(P),
            P1 = P#{chase := Peers ++ maps:get(chase, P)},
            _ = self() ! {next_attempt, Key},
            State#{pending := maps:put(Key, P1, Pending)}
    end.

drop_caller(MRef, State = #{pending := Pending0}) ->
    Pending =
        maps:filtermap(
            fun(_Key, P) ->
                case [C || C = {_F, _Pid, R} <- maps:get(callers, P), R =/= MRef] of
                    [] ->
                        cancel_timer(P),
                        false;
                    Live ->
                        {true, P#{callers := Live}}
                end
            end,
            Pending0
        ),
    State#{pending := Pending}.

fail(Key, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            cancel_timer(P),
            reply_all(maps:get(callers, P), {error, not_found}),
            State#{pending := maps:remove(Key, Pending)}
    end.

reply_all(Callers, Reply) ->
    lists:foreach(
        fun({From, _Pid, MRef}) ->
            erlang:demonitor(MRef, [flush]),
            gen_server:reply(From, Reply)
        end,
        Callers
    ).

cancel_timer(P) ->
    case maps:get(timer, P, undefined) of
        undefined ->
            ok;
        Ref ->
            _ = erlang:cancel_timer(Ref),
            ok
    end.
