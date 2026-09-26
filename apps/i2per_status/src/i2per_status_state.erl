-module(i2per_status_state).

-moduledoc """
Snapshot collector for the status web service.

Keeps the latest view of one `i2per` router — realtime via a subscription to
the router's `m:i2p_events` bus, plus a periodic poll fallback over the same
Erlang distribution. The router may be on this node or any connected node
(`router_node` app env of `i2per_status`, default: this node); it may also be
absent entirely, which is expected state, not an error.

## Usage

```erlang
i2per_status_state:snapshot().
%% => #{online => true, router_node => node(), identity => <<...>>,
%%      peers => #{...}, tunnels => #{...}, netdb => #{...},
%%      sessions => N, events => #{...}}
```
""".

-behaviour(gen_server).

-export([start_link/0, snapshot/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(POLL_MS, 5000).
-define(RPC_TIMEOUT_MS, 2000).

-doc "Start the collector. Registered locally as `i2per_status_state`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Current view of the monitored router.

Output: `t:snapshot/0` — `online` is false whenever the last poll could not
reach the router; event counters accumulate what the bus delivered.
""".
-spec snapshot() -> snapshot().
snapshot() ->
    gen_server:call(?MODULE, snapshot).

-type counters() :: #{
    tunnel_built => non_neg_integer(),
    tunnel_failed => non_neg_integer(),
    tunnel_expired => non_neg_integer(),
    leaseset_published => non_neg_integer(),
    sam_session_created => non_neg_integer(),
    sam_session_closed => non_neg_integer()
}.

-doc "Latest known state of the observed router.".
-type snapshot() :: #{
    online := boolean(),
    router_node := node(),
    subscribed := boolean(),
    identity => binary(),
    peers => #{connected => non_neg_integer(), other => non_neg_integer()},
    tunnels => #{
        outbound => non_neg_integer(),
        inbound => non_neg_integer(),
        transit => non_neg_integer(),
        pending => non_neg_integer()
    },
    netdb => #{ri => non_neg_integer(), ls => non_neg_integer()},
    sessions => non_neg_integer(),
    events := counters()
}.

%% %%%%% %%% gen_server %%%%% %%%

init([]) ->
    RouterNode =
        case application:get_env(i2per_status, router_node) of
            {ok, N} -> N;
            undefined -> node()
        end,
    %% Node-lifecycle watch: nodeup fires once the router becomes reachable
    %% (a wake-up ping makes sure a first connect actually happens).
    ok = net_kernel:monitor_nodes(true),
    wake(RouterNode),
    Subscribed = subscribe(RouterNode),
    erlang:send_after(0, self(), poll),
    {ok, #{
        router_node => RouterNode,
        subscribed => Subscribed,
        online => false,
        view => offline_view(),
        events => empty_counters()
    }}.

handle_call(snapshot, _From, State) ->
    {reply, build_snapshot(State), State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Realtime path: one message per bus event.
handle_info({event, Event}, #{events := Events0} = State) ->
    Events = bump(Event, Events0),
    {noreply, State#{events := Events}};
%% Reconnect path: resubscribe when the router node comes back.
handle_info({nodeup, Node}, #{router_node := Node} = State) ->
    Subscribed = subscribe(Node),
    erlang:send_after(0, self(), poll),
    {noreply, State#{subscribed => Subscribed}};
handle_info({nodedown, Node}, #{router_node := Node} = State) ->
    {noreply, State#{online := false, view := offline_view()}};
handle_info(poll, State) ->
    State1 = poll_once(State),
    erlang:send_after(?POLL_MS, self(), poll),
    {noreply, State1};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% %%%%% %%% Subscription %%%%% %%%

%% Trigger the distribution connection attempt so `nodeup` will fire; a
%% pang is fine — the retry happens on whatever nodeup eventually reports.
wake(Node) when Node =:= node() ->
    ok;
wake(Node) ->
    _ = net_adm:ping(Node),
    ok.

%% Attach the router-side forwarder (`m:i2p_events_forward` ships with the
%% router — handler modules run on the manager's node, so we cannot install
%% our own code there). The call EXITS when the target node is unreachable;
%% that absence is expected state here (it is the reason this service
%% exists), so the boundary collapses every outcome into "are we attached".
subscribe(Node) ->
    Result = catch gen_event:add_handler({i2p_events, Node}, i2p_events_forward, [self()]),
    Result =:= ok.

%% bump/2 — fold one bus event into the counters.
bump({tunnel_built, _, _}, Ev) ->
    maps:update_with(tunnel_built, fun(N) -> N + 1 end, 1, Ev);
bump({tunnel_failed, _, _}, Ev) ->
    maps:update_with(tunnel_failed, fun(N) -> N + 1 end, 1, Ev);
bump({tunnel_expired, _}, Ev) ->
    maps:update_with(tunnel_expired, fun(N) -> N + 1 end, 1, Ev);
bump({leaseset_published, _}, Ev) ->
    maps:update_with(leaseset_published, fun(N) -> N + 1 end, 1, Ev);
bump({sam_session_created, _, _}, Ev) ->
    maps:update_with(sam_session_created, fun(N) -> N + 1 end, 1, Ev);
bump({sam_session_closed, _}, Ev) ->
    maps:update_with(sam_session_closed, fun(N) -> N + 1 end, 1, Ev);
bump(_, Ev) ->
    Ev.

empty_counters() ->
    #{
        tunnel_built => 0,
        tunnel_failed => 0,
        tunnel_expired => 0,
        leaseset_published => 0,
        sam_session_created => 0,
        sam_session_closed => 0
    }.

%% %%%%% %%% Polling %%%%% %%%

%% One poll round: every source is independent — a missing piece stays at its
%% previous value instead of poisoning the whole view.
poll_once(#{router_node := Node, online := WasOnline} = State) ->
    View = fetch_all(Node),
    Online = is_map(View),
    State#{
        online => Online,
        view =>
            case Online of
                true -> View;
                false when WasOnline -> offline_view();
                false -> maps:get(view, State)
            end
    }.
%% Fetch everything in one pass over erpc. erpc EXITS ({erpc,noconnection},
%% noproc, timeout) when the router is absent or slow — expected states here,
%% so the boundary collapses them into `error`, which marks offline.
fetch_all(Node) ->
    case catch erpc:call(Node, i2p_status_data, view, [], ?RPC_TIMEOUT_MS) of
        View when is_map(View) -> View;
        _ -> error
    end.
offline_view() ->
    #{}.

build_snapshot(#{router_node := Node, subscribed := Sub, events := Events} = State) ->
    Base = #{
        online => maps:get(online, State),
        router_node => Node,
        subscribed => Sub,
        events => Events
    },
    case maps:get(view, State) of
        #{} = View when map_size(View) > 0 -> maps:merge(Base, View);
        _ -> Base
    end.
