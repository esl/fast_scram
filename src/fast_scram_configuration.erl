-module(fast_scram_configuration).

-include("types.hrl").
-define(DEFAULT_NONCE_SIZE, 16).
-define(f, #fast_scram_state).

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

set_val_in_state(cached_challenge, {It, Salt}, ?f{data = PD} = St)
  when ?is_positive_integer(It), is_binary(Salt) ->
    Challenge = #challenge{it_count = It, salt = Salt},
    St?f{data = PD#{challenge => Challenge}};
set_val_in_state(cached_challenge, {Salt, It}, ?f{data = PD} = St)
  when ?is_positive_integer(It), is_binary(Salt) ->
    Challenge = #challenge{it_count = It, salt = Salt},
    St?f{data = PD#{challenge => Challenge}};

set_val_in_state(retrieve_mechanism, Fun, ?f{data = PD} = St)
  when is_function(Fun, 1); is_function(Fun, 2) ->
    St?f{data = PD#{retrieve_mechanism => Fun}};

set_val_in_state(WrongKey, _, ?f{}) ->
    {error, wrong_key, WrongKey};
set_val_in_state(_, _, {error, wrong_key, _} = Error) ->
    Error.
