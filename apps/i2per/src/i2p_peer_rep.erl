-module(i2p_peer_rep).

-moduledoc """
Per-peer reliability tracking: the router's Failure table.

Records connection outcomes per peer — successful connects against failed
connects and drops — separately from the connection manager's
(`m:i2p_peer`) transient conn/monitor/backoff state, and persists them so a
restart does not forget which peers can be relied on. Tunnel hop selection
(`m:i2p_tunnel_build`) consults `f:avoided/1` to skip repeatedly unreliable
hops while still falling back to them when no better peer exists.

Like the NetDb process (`m:i2p_netdb_srv`), this is a `gen_server` registered
locally as `i2p_peer_rep`, a `permanent` child of `m:i2per_sup`: its state is
supplemental bookkeeping, so a crash is harmless and a restart re-loads the
last snapshot.

## Reliability model

Each peer tracks:

- `ok` — number of successful connections;
- `fail` — number of connection failures and drops;
- `last_ok` / `last_fail` — wall-clock seconds of the most recent event.

A peer is *avoided* (skipped as a tunnel hop while a better candidate exists)
once it has failed at least `?FAIL_THRESHOLD` times, has more failures than
successes, and its latest failure is still inside the `?FAIL_WINDOW_SECONDS`
window — old failures decay away. Unknown peers are never avoided.
`f:protect/1` exempts a peer (seeds and other boot-critical routers) from
avoidance regardless of its record.

## Persistence

When app env `i2per` -> `data_dir` names a directory, the table is saved to
`peer_rep.bin` inside that directory on shutdown and periodically (every
`?AUTOSAVE_MS`), and loaded back on startup. A missing or corrupt file starts
an empty table. Without a `data_dir` the table is memory-only.

All signal functions tolerate the server being absent — they become no-ops —
so emitters (`m:i2p_peer`) never crash over telemetry, and hop selection falls
back to distance-only when the server is not running.

## Usage

```erlang
%% Record outcomes from the connection manager.
i2p_peer_rep:connected(PeerHash),
i2p_peer_rep:connect_failed(PeerHash),

%% Keep a boot-critical peer selectable no matter what.
i2p_peer_rep:protect(SeedHash),

%% Ask whether a peer is currently blacklisted from tunnel hops.
boolean() = i2p_peer_rep:avoided(PeerHash),
```
""".

-behaviour(gen_server).

-export([
    start_link/0,
    connected/1,
    connect_failed/1,
    protect/1,
    avoided/1,
    status/0,
    snapshot/0,
    save/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([rep/0]).

-define(REP_FILE, "peer_rep.bin").
-define(FILE_HEADER, "I2PREP").
-define(FILE_VERSION, 1).
-define(AUTOSAVE_MS, 60000).
-define(FAIL_THRESHOLD, 3).
-define(FAIL_WINDOW_SECONDS, 86400).

-doc """
One peer's reliability record: the lifetime counters `ok` (successful connects)
and `fail` (failed connects and drops) plus `last_ok`/`last_fail`, the
wall-clock seconds of the most recent of each.
""".
-type rep() :: #{
    ok := non_neg_integer(),
    fail := non_neg_integer(),
    last_ok := non_neg_integer(),
    last_fail := non_neg_integer()
}.

-doc "Start the reliability store, registered locally as `i2p_peer_rep`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Record a successful connection.

Input: `Hash` — the peer's router hash. Output: `ok`. Bumps the peer's `ok`
counter and `last_ok`. A no-op when the server is not running.
""".
-spec connected(i2p_crypto:hash()) -> ok.
connected(Hash) ->
    cast({connected, Hash}).

-doc """
Record a connection failure or drop.

Input: `Hash` — the peer's router hash. Output: `ok`. Bumps the peer's `fail`
counter and `last_fail`. A no-op when the server is not running.
""".
-spec connect_failed(i2p_crypto:hash()) -> ok.
connect_failed(Hash) ->
    cast({connect_failed, Hash}).

-doc """
Exempt a peer from avoidance.

Input: `Hash` — the peer's router hash. Output: `ok`. The peer is never
reported avoided by `f:avoided/1`, whatever its record — for boot-critical
peers such as seeds. A no-op when the server is not running.
""".
-spec protect(i2p_crypto:hash()) -> ok.
protect(Hash) ->
    cast({protect, Hash}).

-doc """
Ask whether a peer should currently be skipped as a tunnel hop.

Input: `Hash` — the peer's router hash. Output: `true` when the peer's record
meets the avoidance rule and it is not protected, `false` otherwise — also for
unknown peers, and whenever the server is not running (selection then falls
back to distance-only).
""".
-spec avoided(i2p_crypto:hash()) -> boolean().
avoided(Hash) ->
    call({avoided, Hash}, false).

-doc """
Inspect the reliability table.

Input: none. Output: a map of peer hash to `#{ok => ..., fail => ...,
avoided => boolean()}` — lifetime counters plus the current avoidance verdict.
""".
-spec status() -> #{i2p_crypto:hash() => map()}.
status() ->
    gen_server:call(?MODULE, status).

-doc """
Return the raw reliability table.

Input: none. Output: the live per-peer record map (hash -> `t:rep/0`), for
persistence and operator inspection.
""".
-spec snapshot() -> #{i2p_crypto:hash() => rep()}.
snapshot() ->
    gen_server:call(?MODULE, snapshot).

-doc """
Flush the reliability table to disk.

Input: none. Output: `ok` when saved (or no `data_dir` is configured), or
`{error, Reason}` when the write fails. Called periodically and on shutdown;
exposed for operator and test use, mirroring `f:save/0` in `m:i2p_netdb_srv`.
""".
-spec save() -> ok | {error, term()}.
save() ->
    gen_server:call(?MODULE, save).

init([]) ->
    Table = load_table(),
    Ref = erlang:send_after(?AUTOSAVE_MS, self(), autosave),
    {ok, #{table => Table, protected => #{}, autosave_ref => Ref}}.

handle_call({avoided, Hash}, _From, State) ->
    {reply, is_avoided(Hash, State), State};
handle_call(status, _From, #{table := Table} = State) ->
    Summary = maps:map(
        fun(Hash, Rep) ->
            #{
                ok => maps:get(ok, Rep),
                fail => maps:get(fail, Rep),
                avoided => is_avoided(Hash, State)
            }
        end,
        Table
    ),
    {reply, Summary, State};
handle_call(snapshot, _From, #{table := Table} = State) ->
    {reply, Table, State};
handle_call(save, _From, #{table := Table} = State) ->
    {reply, save_to_disk(Table), State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({connected, Hash}, State) ->
    {noreply, record(Hash, ok, State)};
handle_cast({connect_failed, Hash}, State) ->
    {noreply, record(Hash, fail, State)};
handle_cast({protect, Hash}, #{protected := Protected} = State) ->
    {noreply, State#{protected := maps:put(Hash, true, Protected)}};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(autosave, #{table := Table} = State) ->
    _ = save_to_disk(Table),
    Ref = erlang:send_after(?AUTOSAVE_MS, self(), autosave),
    {noreply, State#{autosave_ref := Ref}};
handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #{table := Table}) ->
    _ = save_to_disk(Table),
    ok.

%%%%%%%%%% %%% Internal %%%%%%%

cast(Msg) ->
    case whereis(?MODULE) of
        undefined ->
            ok;
        _ ->
            gen_server:cast(?MODULE, Msg)
    end.

call(Msg, Default) ->
    case whereis(?MODULE) of
        undefined ->
            Default;
        _ ->
            gen_server:call(?MODULE, Msg)
    end.

%% Bump one counter and its timestamp for a peer, seeding a fresh record when
%% the peer is not tracked yet.
record(Hash, Kind, #{table := Table} = State) ->
    Now = erlang:system_time(second),
    Rep0 = maps:get(Hash, Table, #{ok => 0, fail => 0, last_ok => 0, last_fail => 0}),
    Rep =
        case Kind of
            ok -> Rep0#{ok := maps:get(ok, Rep0) + 1, last_ok := Now};
            fail -> Rep0#{fail := maps:get(fail, Rep0) + 1, last_fail := Now}
        end,
    State#{table := maps:put(Hash, Rep, Table)}.

is_avoided(Hash, #{protected := Protected, table := Table}) ->
    case maps:is_key(Hash, Protected) of
        true ->
            false;
        false ->
            case maps:find(Hash, Table) of
                {ok, Rep} -> avoided_by_rep(Rep, erlang:system_time(second));
                error -> false
            end
    end.

%% Avoidance rule: enough failures, failures outnumber successes, and the
%% worst of it is recent enough to still matter.
avoided_by_rep(#{fail := Fail, ok := Ok, last_fail := LastFail}, Now) ->
    Fail >= ?FAIL_THRESHOLD andalso Fail > Ok andalso Now - LastFail =< ?FAIL_WINDOW_SECONDS.

load_table() ->
    case data_dir() of
        {ok, Dir} ->
            Path = filename:join(Dir, ?REP_FILE),
            case file:read_file(Path) of
                {ok, Bin} ->
                    case decode(Bin) of
                        {ok, Table} when is_map(Table) -> Table;
                        {error, _} -> #{}
                    end;
                {error, _} ->
                    #{}
            end;
        undefined ->
            #{}
    end.

decode(<<?FILE_HEADER, ?FILE_VERSION:8, Payload/binary>>) ->
    try binary_to_term(Payload, [safe]) of
        Table -> {ok, Table}
    catch
        error:badarg -> {error, parse_error}
    end;
decode(_) ->
    {error, parse_error}.

encode(Table) ->
    <<?FILE_HEADER, ?FILE_VERSION:8, (term_to_binary(Table))/binary>>.

save_to_disk(Table) ->
    case data_dir() of
        {ok, Dir} ->
            Path = filename:join(Dir, ?REP_FILE),
            Bin = encode(Table),
            case filelib:ensure_dir(Path) of
                ok ->
                    case file:write_file(Path, Bin) of
                        ok -> ok;
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        undefined ->
            ok
    end.

data_dir() ->
    case application:get_env(i2per, data_dir) of
        {ok, Dir} when is_list(Dir) -> {ok, Dir};
        _ -> undefined
    end.
