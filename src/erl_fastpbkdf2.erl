-module(erl_fastpbkdf2).
-on_load(load/0).

-export([fastpbkdf2_hmac_sha/4]).

-spec fastpbkdf2_hmac_sha(1 | 256 | 512, binary(), binary(), non_neg_integer()) -> binary().
fastpbkdf2_hmac_sha(_Hash, _Password, _Salt, _IterationCount) ->
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
