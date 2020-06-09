-module(fast_scram).
-on_load(load/0).

-export([hi/4]).

-type sha_type() :: crypto:sha1() | crypto:sha2().

-spec hi(sha_type(), binary(), binary(), non_neg_integer()) -> binary().
hi(_Hash, _Password, _Salt, _IterationCount) ->
    erlang:nif_error(not_loaded).

%%%===================================================================
%%% Load NIF
%%%===================================================================
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
