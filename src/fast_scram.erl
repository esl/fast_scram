-module(fast_scram).
-on_load(load/0).

-include("types.hrl").
-include_lib("kernel/include/logger.hrl").

-type configuration() :: map().

-type next_message() :: binary().
-type error_message() :: binary().

-spec mech_new(configuration()) ->
    {ok, fast_scram_state()} |
    {continue, fast_scram_state()} |
    {error, binary()}.

-spec mech_append(fast_scram_state(), configuration()) ->
    {ok, fast_scram_state()} |
    {continue, fast_scram_state()} |
    {error, binary()}.

-spec mech_step(fast_scram_state(), binary()) ->
    {ok,       <<>>,            fast_scram_state()} |
    {continue, next_message(),  fast_scram_state()} |
    {error,    error_message(), fast_scram_state()}.

-export([hi/4]).

-export([mech_new/1, mech_append/2, mech_step/2]).

%%%===================================================================
%%% CONFIGURATION
%%%===================================================================
%% Mandatory for a client are the name and the nonce_size
%% Optionally, the client can tell us if he has channel-binding and its data
%% The client might also have cached the salted_password
%% The client doesn't usually know about the challenge yet, so that field is for now empty
%% We DECIDE the nonce, to ensure its safety, it's a design decision of this library
mech_new(Config) ->
    fast_scram_configuration:mech_new(Config).

mech_append(State, Config) ->
    fast_scram_configuration:mech_append(State, Config).

%%%===================================================================
%%% MECHANISM STEPS
%%%===================================================================
%%% CLIENT STEPS
mech_step(#fast_scram_state{
             step = 1,
             nonce = Nonce,
             channel_binding = CbConfig,
             data = PrivData
            } = State, <<>>) ->
    {GS2Header, ClientFirstBare} = fast_scram_attributes:client_first_message(
                                     CbConfig, Nonce, PrivData),
    ClientFirstMessage = <<GS2Header/binary, ClientFirstBare/binary>>,
    NewState = fast_scram_parse_rules:append_to_auth_message_in_state(State, ClientFirstBare),
    {continue, ClientFirstMessage, NewState#fast_scram_state{step = 3}};

mech_step(#fast_scram_state{step = 3} = State, ServerIn) ->
    case parse_server_first_message(ServerIn, State) of
        {ok, #fast_scram_state{
                nonce = Nonce,
                challenge = Challenge,
                channel_binding = CbConfig,
                scram_definitions = Scram0,
                data = PrivData
               } = NewState} ->
            ClientFinalNoProof = fast_scram_attributes:client_final_message_without_proof(
                                   CbConfig, Nonce, PrivData),
            Scram1 = fast_scram_parse_rules:append_to_auth_message(
                       Scram0, <<",", ClientFinalNoProof/binary>>),
            Scram2 = scram_definitions_pipe(Scram1, Challenge, PrivData),
            ClientProof = Scram2#scram_definitions.client_proof,
            ClientFinalMessage = fast_scram_attributes:client_final_message(
                                   ClientFinalNoProof, ClientProof),
            NewState1 = NewState#fast_scram_state{scram_definitions = Scram2},
            {continue, ClientFinalMessage, NewState1#fast_scram_state{step = 5}};
        {error, Reason} ->
            {error, Reason, State}
    end;

mech_step(#fast_scram_state{step = 5} = State, ServerIn) ->
    case parse_server_final_message(ServerIn, State) of
        {ok, NewState} ->
            {ok, <<>>, NewState};
        {error, Reason} ->
            {error, Reason, State}
    end;

%%% SERVER STEPS
mech_step(#fast_scram_state{step = 2} = State, ClientIn) ->
    case parse_client_first_message(ClientIn, State) of
        {ok, #fast_scram_state{
                nonce = Nonce,
                challenge = Challenge,
                scram_definitions = Scram0,
                data = PrivData
               } = NewState} ->
            ServerFirstMsg = fast_scram_attributes:server_first_message(Nonce, Challenge),
            Scram1 = scram_definitions_pipe(Scram0, Challenge, PrivData),
            Scram2 = fast_scram_parse_rules:append_to_auth_message(
                       Scram1, <<",", ServerFirstMsg/binary>>),
            NewState1 = NewState#fast_scram_state{scram_definitions = Scram2},
            {continue, ServerFirstMsg, NewState1#fast_scram_state{step = 4}};
        {error, Reason} ->
            {error, Reason, State}
    end;

mech_step(#fast_scram_state{step = 4} = State, ClientIn) ->
    case parse_client_final_message(ClientIn, State) of
        {ok, #fast_scram_state{
                challenge = Challenge,
                scram_definitions = Scram0,
                data = PrivData
               } = NewState} ->
            GivenClientProof = maps:get(client_proof, PrivData),
            Scram = scram_definitions_pipe(Scram0, Challenge, PrivData),
            NewState1 = NewState#fast_scram_state{scram_definitions = Scram},
            case check_proof(Scram, GivenClientProof) of
                ok ->
                    ServerSignature = Scram#scram_definitions.server_signature,
                    ServerLastMessage = fast_scram_attributes:server_final_message(
                                         base64:encode(ServerSignature)),
                    {ok, ServerLastMessage, NewState1#fast_scram_state{step = 6}};
                {error, Reason} ->
                    ServerLastMessage = fast_scram_attributes:server_final_message({error, Reason}),
                    {error, ServerLastMessage, NewState1}
            end;
        {error, Reason} ->
            ServerLastMessage = fast_scram_attributes:server_final_message({error, Reason}),
            {error, ServerLastMessage, State}
    end.


-spec check_proof(scram_definitions(), binary()) -> ok | {error, binary()}.
check_proof(#scram_definitions{client_proof = CalculatedClientProof}, GivenClientProof)
  when CalculatedClientProof =:= GivenClientProof ->
    ok;
check_proof(#scram_definitions{hash_method = HashMethod,
                               client_proof = <<>>,
                               stored_key = StoredKey,
                               client_signature = ClientSignature}, GivenClientProof) ->
    ClientKey = fast_scram_definitions:client_proof(GivenClientProof, ClientSignature),
    CalculatedStoredKey = fast_scram_definitions:stored_key(HashMethod, ClientKey),
    case CalculatedStoredKey =:= StoredKey of
        true -> ok;
        _ -> {error, <<"invalid-proof">>}
    end;
check_proof(_, _) ->
    {error, <<"invalid-proof">>}.

-spec scram_definitions_pipe(scram_definitions(), challenge(), map()) ->
    scram_definitions().
%% This is just like in the first option, but this time we have the auth message,
%% so we can calculate all the steps
%%%%%% CLIENT STEP
scram_definitions_pipe(
  #scram_definitions{hash_method = HashMethod, salted_password = <<>>, auth_message = AuthMessage} = Scram,
  #challenge{salt = Salt, it_count = ItCount},
  #{password := Password}) ->
    SaltedPassword = fast_scram_definitions:salted_password(HashMethod, Password, Salt, ItCount),
    ClientKey = fast_scram_definitions:client_key(HashMethod, SaltedPassword),
    StoredKey = fast_scram_definitions:stored_key(HashMethod, ClientKey),
    ClientSignature = fast_scram_definitions:client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = fast_scram_definitions:client_proof(ClientKey, ClientSignature),
    ServerKey = fast_scram_definitions:server_key(HashMethod, SaltedPassword),
    ServerSignature = fast_scram_definitions:server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
       salted_password = SaltedPassword,
       client_key = ClientKey,
       stored_key = StoredKey,
       auth_message = AuthMessage,
       client_signature = ClientSignature,
       client_proof = ClientProof,
       server_key = ServerKey,
       server_signature = ServerSignature
      };
scram_definitions_pipe(
  #scram_definitions{hash_method = HashMethod, salted_password = SaltedPassword, auth_message = AuthMessage} = Scram,
  #challenge{} = GivenChallenge,
  #{challenge := StoredChallenge} = Data) when AuthMessage =/= <<>> ->
    case GivenChallenge =:= StoredChallenge of
        % This means that the client has cached the value correctly
        true ->
            ClientKey = case Scram#scram_definitions.client_key of
                            <<>> -> fast_scram_definitions:client_key(HashMethod, SaltedPassword);
                            CK -> CK
                        end,
            StoredKey = fast_scram_definitions:stored_key(HashMethod, ClientKey),
            ClientSignature = fast_scram_definitions:client_signature(HashMethod, StoredKey, AuthMessage),
            ClientProof = fast_scram_definitions:client_proof(ClientKey, ClientSignature),
            ServerKey = case Scram#scram_definitions.server_key of
                            <<>> -> fast_scram_definitions:server_key(HashMethod, SaltedPassword);
                            SK -> SK
                        end,
            ServerSignature = fast_scram_definitions:server_signature(HashMethod, ServerKey, AuthMessage),
            Scram#scram_definitions{
              salted_password = SaltedPassword,
              client_key = ClientKey,
              stored_key = StoredKey,
              auth_message = AuthMessage,
              client_signature = ClientSignature,
              client_proof = ClientProof,
              server_key = ServerKey,
              server_signature = ServerSignature
             };
        false ->
            ScramWithoutCached = #scram_definitions{hash_method = HashMethod, auth_message = AuthMessage},
            DataWithoutCached = maps:remove(challenge, Data),
            scram_definitions_pipe(ScramWithoutCached, GivenChallenge, DataWithoutCached)
    end;
scram_definitions_pipe(
  #scram_definitions{hash_method = HashMethod,
                     client_key = ClientKey,
                     stored_key = StoredKey,
                     auth_message = AuthMessage,
                     server_key = ServerKey
                    } = Scram,
  #challenge{}, #{}) when StoredKey =/= <<>>, ServerKey =/= <<>>, ClientKey =/= <<>> ->
    ClientSignature = fast_scram_definitions:client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = fast_scram_definitions:client_proof(ClientKey, ClientSignature),
    ServerSignature = fast_scram_definitions:server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
      client_proof = ClientProof,
      client_signature = ClientSignature,
      server_signature = ServerSignature
     };
scram_definitions_pipe(
  #scram_definitions{hash_method = HashMethod,
                     stored_key = StoredKey,
                     auth_message = AuthMessage,
                     server_key = ServerKey
                    } = Scram,
  #challenge{}, #{}) when StoredKey =/= <<>>, ServerKey =/= <<>> ->
    ClientSignature = fast_scram_definitions:client_signature(HashMethod, StoredKey, AuthMessage),
    ServerSignature = fast_scram_definitions:server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
      client_signature = ClientSignature,
      server_signature = ServerSignature
     };
scram_definitions_pipe(
  #scram_definitions{hash_method = HashMethod,
                     salted_password = SaltedPassword,
                     client_key = <<>>,
                     auth_message = AuthMessage} = Scram,
  #challenge{}, #{}) when SaltedPassword =/= <<>>, AuthMessage =/= <<>> ->
    ClientKey = fast_scram_definitions:client_key(HashMethod, SaltedPassword),
    StoredKey = fast_scram_definitions:stored_key(HashMethod, ClientKey),
    ClientSignature = fast_scram_definitions:client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = fast_scram_definitions:client_proof(ClientKey, ClientSignature),
    ServerKey = fast_scram_definitions:server_key(HashMethod, SaltedPassword),
    ServerSignature = fast_scram_definitions:server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
      client_key = ClientKey,
      stored_key = StoredKey,
      client_signature = ClientSignature,
      client_proof = ClientProof,
      server_key = ServerKey,
      server_signature = ServerSignature
     };
scram_definitions_pipe(
  #scram_definitions{hash_method = HashMethod,
                     salted_password = SaltedPassword,
                     client_key = ClientKey,
                     stored_key = StoredKey,
                     auth_message = AuthMessage} = Scram,
  #challenge{},
  #{}) when SaltedPassword =/= <<>>, AuthMessage =/= <<>> ->
    ClientSignature = fast_scram_definitions:client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = fast_scram_definitions:client_proof(ClientKey, ClientSignature),
    ServerKey = fast_scram_definitions:server_key(HashMethod, SaltedPassword),
    ServerSignature = fast_scram_definitions:server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
      client_signature = ClientSignature,
      client_proof = ClientProof,
      server_key = ServerKey,
      server_signature = ServerSignature
     };
scram_definitions_pipe(Scram, _, _) ->
    ?LOG_DEBUG(#{what => scram_no_pipe_match}),
    Scram.


%%%===================================================================
%%% SCRAM parsing full messages
%%%===================================================================
%  client-first-message =
%        gs2-cbind-flag "," [authzid] "," [reserved-mext ","] username "," nonce ["," extensions]
-spec parse_client_first_message(binary(), fast_scram_state()) -> parse_return().
parse_client_first_message(ClientIn, State0) ->
    Rules = [
             fun fast_scram_parse_rules:parse_gs2_cbind_flag/2,
             fun fast_scram_parse_rules:parse_authzid/2,
             fun fast_scram_parse_rules:parse_reserved_mext/2,
             fun fast_scram_parse_rules:parse_username/2,
             fun fast_scram_parse_rules:parse_nonce/2,
             fun fast_scram_parse_rules:parse_extensions/2
            ],
    Chunks = binary:split(ClientIn, <<",">>, [global]),
    case match_rules(Chunks, Rules, State0) of
        {UnusedRules, State1 = #fast_scram_state{}}
          when is_list(UnusedRules), length(UnusedRules) == 1 ->
            ClientFirstMsgBare = extract_client_first_msg_bare_from_first(Chunks, ClientIn),
            State2 = fast_scram_parse_rules:append_to_auth_message_in_state(
                          State1, ClientFirstMsgBare),
            {ok, State2};
        {error, Reason} ->
            {error, Reason}
    end.

% server-first-message =
%                   [reserved-mext ","] nonce "," salt ","
%                   iteration-count ["," extensions]
-spec parse_server_first_message(binary(), fast_scram_state()) -> parse_return().
parse_server_first_message(ServerIn, State0) ->
    Rules = [
             fun fast_scram_parse_rules:parse_reserved_mext/2,
             fun fast_scram_parse_rules:parse_nonce/2,
             fun fast_scram_parse_rules:parse_salt/2,
             fun fast_scram_parse_rules:parse_iteration_count/2,
             fun fast_scram_parse_rules:parse_extensions/2
            ],
    ServerInChunks = binary:split(ServerIn, <<",">>, [global]),
    case match_rules(ServerInChunks, Rules, State0) of
        {UnusedRules, State1 = #fast_scram_state{}}
          when is_list(UnusedRules), length(UnusedRules) == 1 ->
            State2 = fast_scram_parse_rules:append_to_auth_message_in_state(
                       State1, <<",", ServerIn/binary>>),
            {ok, State2};
        {error, Reason} ->
            {error, Reason}
    end.

% client-final-message =
%                   channel-binding "," nonce ["," extensions] "," proof
-spec parse_client_final_message(binary(), fast_scram_state()) -> parse_return().
parse_client_final_message(ClientIn, State0) ->
    Rules = [
             fun fast_scram_parse_rules:parse_channel_binding/2,
             fun fast_scram_parse_rules:parse_nonce/2,
             fun fast_scram_parse_rules:parse_extensions/2,
             fun fast_scram_parse_rules:parse_proof/2
            ],
    ClientInList = binary:split(ClientIn, <<",">>, [global]),
    case match_rules(ClientInList, Rules, State0) of
        {UnusedRules, State1 = #fast_scram_state{}}
          when is_list(UnusedRules), length(UnusedRules) == 0 ->
            ClientFinalNoProof = extract_client_final_no_proof(ClientIn),
            State2 = fast_scram_parse_rules:append_to_auth_message_in_state(
                       State1, <<",", ClientFinalNoProof/binary>>),
            {ok, State2};
        {error, Reason} ->
            {error, Reason};
        {_, #fast_scram_state{}} ->
            {error, <<"other-error">>}
    end.

% server-final-message = (server-error / verifier)
%                   ["," extensions]
-spec parse_server_final_message(binary(), fast_scram_state()) -> parse_return().
parse_server_final_message(ServerIn, State0) ->
    Rules = [
             fun fast_scram_parse_rules:parse_server_error_or_verifier/2,
             fun fast_scram_parse_rules:parse_extensions/2
            ],
    ServerInChunks = binary:split(ServerIn, <<",">>, [global]),
    case match_rules(ServerInChunks, Rules, State0) of
        {UnusedRules, State1 = #fast_scram_state{}}
          when is_list(UnusedRules), length(UnusedRules) == 1 ->
            {ok, State1};
        {error, Reason} ->
            {error, Reason}
    end.

extract_client_first_msg_bare_from_first([Gs2BindFlag, AuthZID | _], ClientIn) ->
    NStart = byte_size(Gs2BindFlag) + byte_size(AuthZID) + 2,
    binary:part(ClientIn, {NStart, byte_size(ClientIn) - NStart}).

extract_client_final_no_proof(ClientIn) ->
    {PStart, _} = binary:match(ClientIn, <<",p=">>),
    binary:part(ClientIn, {0, PStart}).

%%%===================================================================
%%% Match parsing rules
%%%===================================================================
match_rules(Inputs, Rules, State) ->
    lists:foldl(
      fun(_, {error, Reason}) ->
              {error, Reason};
         (Input, {RulesLeft, St}) ->
              apply_rules_until_match(Input, RulesLeft, St)
      end, {Rules, State}, Inputs).

apply_rules_until_match(_, [], _) ->
    {error, <<"error-too-much-input">>};
apply_rules_until_match(Input, [Rule | RulesLeft], State) ->
    case Rule(Input, State) of
        {ok, NewState} ->
            {RulesLeft, NewState};
        {skip_rule, State} ->
            apply_rules_until_match(Input, RulesLeft, State);
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Load NIF
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
