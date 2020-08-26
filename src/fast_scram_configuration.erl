-module(fast_scram_configuration).

-include("types.hrl").
-define(DEFAULT_NONCE_SIZE, 16).
-define(f, #fast_scram_state).

-export([mech_new/1, mech_append/2]).

%% Required fields will be:
%% 1. entity
%% 2. hash method
%% 3. if client then username is required
%% 4. if server then it_count and salt are required
%% 5. SOME SUFFICIENT COMBINATION OF SCRAM DATA

% We first match that the strictly required is available
mech_new(#{entity := client,
           hash_method := HashMethod, username := _, % Required for a client
           auth_data := AuthData
          } = Config) ->
    St = ?f{step = 1, scram_definitions = #scram_definitions{hash_method = HashMethod}},
    build_state(St, AuthData, Config);
mech_new(#{entity := server,
           hash_method := HashMethod,
           it_count := _, salt := _,
           auth_data := AuthData % Universally required, will be verified downstream
          } = Config) ->
    St = ?f{step = 2, scram_definitions = #scram_definitions{hash_method = HashMethod}},
    build_state(St, AuthData, Config);
mech_new(#{entity := server, hash_method := HashMethod} = Config) ->
    St = ?f{step = 2, scram_definitions = #scram_definitions{hash_method = HashMethod}},
    Config1 = ensure_full_config(Config),
    Res = maps:fold(fun set_val_in_state/3, St, Config1),
    case Res of
        Res = ?f{} -> {continue, Res};
        Error -> Error
    end;
mech_new(_) ->
    {error, <<"Missing mandatory fields">>}.

mech_append(?f{step = 2} = St, #{it_count := _, salt := _, auth_data := AuthData} = Config) ->
    build_state(St, AuthData, Config).

build_state(St, AuthData, Config) ->
    % Then we verify that the scram data provided is exact
    case verify_mandatory_scram_data(maps:keys(AuthData)) of
        true ->
            Config1 = ensure_full_config(Config),
            ToFoldThrough = maps:merge(AuthData, maps:without([auth_data], Config1)),
            Res = maps:fold(fun set_val_in_state/3, St, ToFoldThrough),
            case Res of
                Res = ?f{} -> {ok, Res};
                Error -> Error
            end;
        false ->
            {error, <<"Invalid authentication configuration">>}
    end.

ensure_full_config(Config) ->
    case (not maps:is_key(nonce_size, Config) andalso not maps:is_key(nonce, Config)) of
        true -> Config#{nonce_size => ?DEFAULT_NONCE_SIZE};
        _ -> Config
    end.

% It will get just a combination of the given atoms and verify that they are the exact one
% Correct combinations:
%   password alone
%       For all other methods, a cached challenge together with a password
%       could be given for verification. If a cached challenge is available,
%       we first verify if it matches the one given by the server
%   salted_password
%   stored_key & server_key
%   client_key & server_key
-type auth_data() :: password | salted_password | client_key | stored_key | server_key.
-spec verify_mandatory_scram_data([auth_data()]) -> boolean().
verify_mandatory_scram_data(List) ->
    case lists:sort(List) of
        [password] -> true;
        [salted_password] -> true;
        [password, salted_password] -> true;
        [password, server_key, stored_key] -> true;
        [client_key, password, server_key] -> true;
        [client_key, server_key] -> true;
        [server_key, stored_key] -> true;
        _ -> false
    end.

%% @doc This only adds a key into the state, verifying typeness, but not if it is repeated.
-type option() :: atom().
-type value() :: term().
-spec set_val_in_state(option(), value(), fast_scram_state()) ->
    fast_scram_state() | {error, atom(), term()}.
set_val_in_state(entity, Ent, ?f{} = St) when is_atom(Ent) ->
    case Ent of
        client -> St?f{step = 1};
        server -> St?f{step = 2}
    end;

set_val_in_state(nonce_size, Num, ?f{} = St) when ?is_positive_integer(Num) ->
    Bin = base64:encode(crypto:strong_rand_bytes(Num)),
    case St?f.step of
        1 -> St?f{nonce = #nonce{client = Bin}};
        2 -> St?f{nonce = #nonce{server = Bin}}
    end;
set_val_in_state(nonce, Bin, ?f{} = St) when is_binary(Bin) ->
    case St?f.step of
        1 -> St?f{nonce = #nonce{client = Bin}};
        2 -> St?f{nonce = #nonce{server = Bin}}
    end;

set_val_in_state(it_count, Num, ?f{challenge = Ch} = St) when ?is_positive_integer(Num) ->
    St?f{challenge = Ch#challenge{it_count = Num}};
set_val_in_state(salt, Bin, ?f{challenge = Ch} = St) when is_binary(Bin) ->
    St?f{challenge = Ch#challenge{salt = Bin}};

set_val_in_state(channel_binding, {Type, Data}, ?f{channel_binding = CB} = St)
  when is_atom(Type) orelse is_binary(Type), is_binary(Data) ->
    St?f{channel_binding = CB#channel_binding{variant = Type, data = Data}};

set_val_in_state(hash_method, HM, ?f{scram_definitions = SD} = St) when ?is_valid_hash(HM) ->
    St?f{scram_definitions = SD#scram_definitions{hash_method = HM}};
set_val_in_state(salted_password, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{salted_password = Bin}};
set_val_in_state(client_key, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{client_key = Bin}};
set_val_in_state(stored_key, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{stored_key = Bin}};
set_val_in_state(client_signature, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{client_signature = Bin}};
set_val_in_state(client_proof, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{client_proof = Bin}};
set_val_in_state(server_key, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{server_key = Bin}};
set_val_in_state(server_signature, Bin, ?f{scram_definitions = SD} = St) when is_binary(Bin) ->
    St?f{scram_definitions = SD#scram_definitions{server_signature = Bin}};

%% Stuff to data
set_val_in_state(username, UN, ?f{data = PD} = St) when is_binary(UN) ->
    St?f{data = PD#{username => UN}};
set_val_in_state(password, PW, ?f{data = PD} = St) when is_binary(PW) ->
    St?f{data = PD#{password => PW}};

set_val_in_state(cached_it_count, Num, ?f{data = PD} = St) when ?is_positive_integer(Num) ->
    Challenge = case maps:get(challenge, PD, undefined) of
                    Ch = #challenge{} -> Ch#challenge{it_count = Num};
                    undefined -> #challenge{it_count = Num}
                end,
    St?f{data = PD#{challenge => Challenge}};
set_val_in_state(cached_salt, Salt, ?f{data = PD} = St) when is_binary(Salt) ->
    Challenge = case maps:get(challenge, PD, undefined) of
                    Ch = #challenge{} -> Ch#challenge{salt = Salt};
                    undefined -> #challenge{salt = Salt}
                end,
    St?f{data = PD#{challenge => Challenge}};

set_val_in_state(WrongKey, _, ?f{}) ->
    {error, wrong_key, WrongKey};
set_val_in_state(_, _, {error, wrong_key, _} = Error) ->
    Error.
