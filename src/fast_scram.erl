-module(fast_scram).
-on_load(load/0).

-include("types.hrl").

-type configuration() :: map().

-spec mech_new(configuration()) ->
    {ok, fast_scram_state()} |
    {continue, fast_scram_state()} |
    {error, binary()}.

-spec mech_append(fast_scram_state(), configuration()) ->
    {ok, fast_scram_state()} |
    {continue, fast_scram_state()} |
    {error, binary()}.

-export([hi/4]).

-export([mech_new/1]).

-export([mech_append/2,
         mech_get/2,
         mech_get/3,
         mech_set/3
        ]).

mech_new(Config) ->
    fast_scram_configuration:mech_new(Config).

mech_append(State, Config) ->
    fast_scram_configuration:mech_append(State, Config).

-spec mech_get(term(), fast_scram_state()) -> term().
mech_get(Key, #fast_scram_state{data = PD}) ->
    maps:get(Key, PD, undefined).

-spec mech_get(term(), fast_scram_state(), term()) -> term().
mech_get(Key, #fast_scram_state{data = PD}, Default) ->
    maps:get(Key, PD, Default).

-spec mech_set(term(), term(), fast_scram_state()) -> fast_scram_state().
mech_set(Key, Value, #fast_scram_state{data = PD} = State) ->
    State#fast_scram_state{data = PD#{Key => Value}}.

%%%===================================================================
%%% NIF
%%%===================================================================
-spec hi(sha_type(), binary(), binary(), non_neg_integer()) -> binary().
hi(_Hash, _Password, _Salt, _IterationCount) ->
    erlang:nif_error(not_loaded).

-spec load() -> any().
load() ->
    code:ensure_loaded(crypto),
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, _} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, ?MODULE_STRING), none).
