%% @private
%% @see fast_scram
-module(fast_scram_configuration).

-include("fast_scram.hrl").
-define(DEFAULT_NONCE_SIZE, 16).

-export([mech_new/1, mech_append/2]).

% We first match that the strictly required is available
mech_new(
    #{
        entity := client,
        hash_method := HashMethod,
        username := _,
        auth_data := AuthData
    } = Config
) ->
    St = #fast_scram_state{
        step = 1, scram_definitions = #scram_definitions{hash_method = HashMethod}
    },
    Res = build_state(St, AuthData, Config),
    maybe_tag_ok(Res);
mech_new(
    #{
        entity := server,
        hash_method := HashMethod,
        retrieve_mechanism := Fun
    } = Config
) when
    is_function(Fun, 1); is_function(Fun, 2)
->
    St = #fast_scram_state{
        step = 2, scram_definitions = #scram_definitions{hash_method = HashMethod}
    },
    Config1 = ensure_full_config(St, Config),
    Res = maps:fold(fun set_val_in_state/3, St, Config1),
    maybe_tag_ok(Res);
mech_new(_) ->
    {error, <<"Wrong configuration">>}.

-spec maybe_tag_ok
    (fast_scram:state()) -> {ok, fast_scram:state()};
    ({error, T1, T2}) -> {error, T1, T2} when
        T1 :: term(), T2 :: term().
maybe_tag_ok(#fast_scram_state{} = St) ->
    {ok, St};
maybe_tag_ok(Error) ->
    Error.

-spec mech_append(fast_scram:state(), fast_scram:configuration()) ->
    fast_scram:state() | {error, binary()}.
mech_append(
    #fast_scram_state{step = 2} = St, #{it_count := _, salt := _, auth_data := AuthData} = Config
) ->
    build_state(St, AuthData, Config);
mech_append(_, _) ->
    {error, <<"Wrong configuration">>}.

build_state(St, AuthData, Config) ->
    case verify_mandatory_scram_data(maps:keys(AuthData)) of
        true ->
            Config1 = ensure_full_config(St, Config),
            ToFoldThrough = maps:merge(AuthData, maps:without([auth_data], Config1)),
            maps:fold(fun set_val_in_state/3, St, ToFoldThrough);
        false ->
            {error, <<"Invalid authentication configuration">>}
    end.

ensure_full_config(#fast_scram_state{nonce = #nonce{client = C, server = S}}, Config) when
    C == <<>>, S == <<>>
->
    case (not maps:is_key(nonce_size, Config) andalso not maps:is_key(nonce, Config)) of
        true -> Config#{nonce_size => ?DEFAULT_NONCE_SIZE};
        _ -> Config
    end;
ensure_full_config(#fast_scram_state{}, Config) ->
    Config.

% It will get just a combination of the given atoms and verify that they are the exact one
% Correct combinations:
%   password alone
%       For all other methods, a cached challenge together with a password
%       could be given for verification. If a cached challenge is available,
%       we first verify if it matches the one given by the server
%   salted_password
%   stored_key & server_key
%   client_key & server_key
-spec verify_mandatory_scram_data([fast_scram:auth_keys()]) -> boolean().
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
-spec set_val_in_state(option(), value(), fast_scram:state()) ->
    fast_scram:state() | {error, atom(), term()}.
set_val_in_state(entity, Ent, #fast_scram_state{} = St) when is_atom(Ent) ->
    case Ent of
        client -> St#fast_scram_state{step = 1};
        server -> St#fast_scram_state{step = 2}
    end;
set_val_in_state(nonce_size, Num, #fast_scram_state{step = 1} = St) when
    ?IS_POSITIVE_INTEGER(Num)
->
    Bin = base64:encode(crypto:strong_rand_bytes(Num)),
    St#fast_scram_state{nonce = #nonce{client = Bin}};
set_val_in_state(nonce_size, Num, #fast_scram_state{step = 2} = St) when
    ?IS_POSITIVE_INTEGER(Num)
->
    Bin = base64:encode(crypto:strong_rand_bytes(Num)),
    St#fast_scram_state{nonce = #nonce{server = Bin}};
set_val_in_state(nonce, Bin, #fast_scram_state{step = 1} = St) when is_binary(Bin) ->
    St#fast_scram_state{nonce = #nonce{client = Bin}};
set_val_in_state(nonce, Bin, #fast_scram_state{step = 2} = St) when is_binary(Bin) ->
    St#fast_scram_state{nonce = #nonce{server = Bin}};
set_val_in_state(it_count, Num, #fast_scram_state{challenge = Ch} = St) when
    ?IS_POSITIVE_INTEGER(Num)
->
    St#fast_scram_state{challenge = Ch#challenge{it_count = Num}};
set_val_in_state(salt, Bin, #fast_scram_state{challenge = Ch} = St) when is_binary(Bin) ->
    St#fast_scram_state{challenge = Ch#challenge{salt = Bin}};
set_val_in_state(channel_binding, {Type, Data}, #fast_scram_state{channel_binding = CB} = St) when
    is_atom(Type) orelse is_binary(Type), is_binary(Data)
->
    St#fast_scram_state{channel_binding = CB#channel_binding{variant = Type, data = Data}};
set_val_in_state(hash_method, HM, #fast_scram_state{scram_definitions = SD} = St) when
    ?IS_VALID_HASH(HM)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{hash_method = HM}};
set_val_in_state(salted_password, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{salted_password = Bin}};
set_val_in_state(client_key, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{client_key = Bin}};
set_val_in_state(stored_key, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{stored_key = Bin}};
set_val_in_state(client_signature, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{client_signature = Bin}};
set_val_in_state(client_proof, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{client_proof = Bin}};
set_val_in_state(server_key, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{server_key = Bin}};
set_val_in_state(server_signature, Bin, #fast_scram_state{scram_definitions = SD} = St) when
    is_binary(Bin)
->
    St#fast_scram_state{scram_definitions = SD#scram_definitions{server_signature = Bin}};
%% Stuff to data
set_val_in_state(username, UN, #fast_scram_state{data = PD} = St) when is_binary(UN) ->
    St#fast_scram_state{data = PD#{username => UN}};
set_val_in_state(password, PW, #fast_scram_state{data = PD} = St) when is_binary(PW) ->
    St#fast_scram_state{data = PD#{password => PW}};
set_val_in_state(cached_challenge, {It, Salt}, #fast_scram_state{data = PD} = St) when
    ?IS_POSITIVE_INTEGER(It), is_binary(Salt)
->
    Challenge = #challenge{it_count = It, salt = Salt},
    St#fast_scram_state{data = PD#{challenge => Challenge}};
set_val_in_state(cached_challenge, {Salt, It}, #fast_scram_state{data = PD} = St) when
    ?IS_POSITIVE_INTEGER(It), is_binary(Salt)
->
    Challenge = #challenge{it_count = It, salt = Salt},
    St#fast_scram_state{data = PD#{challenge => Challenge}};
set_val_in_state(retrieve_mechanism, Fun, #fast_scram_state{data = PD} = St) when
    is_function(Fun, 1); is_function(Fun, 2)
->
    St#fast_scram_state{data = PD#{retrieve_mechanism => Fun}};
set_val_in_state(WrongKey, _, #fast_scram_state{}) ->
    {error, wrong_key, WrongKey};
set_val_in_state(_, _, {error, wrong_key, _} = Error) ->
    Error.
