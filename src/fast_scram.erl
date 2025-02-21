%%% @doc SCRAM implementation, see the `README' for details.
-module(fast_scram).

-include("fast_scram.hrl").

-ifdef(WITHOUT_NIFS).
-type sha_type() :: crypto:sha1() | crypto:sha2().
-else.
-type sha_type() :: crypto:sha1() | crypto:sha2() | sha3_224 | sha3_256 | sha3_384 | sha3_512.
-endif.
%%% Supported underlying hashing algorithms.
-type configuration() :: #{
    entity := client | server,
    hash_method := sha_type(),
    _ => _
}.
%%% Configuration for SCRAM, see the `README' for details.
-type username() :: binary().
%%% Username for the algorithm.
%%%
%%% Required for a client.
-type retrieve_mechanism() ::
    fun((username()) -> configuration())
    | fun((username(), state()) -> {configuration(), state()}).
%%% Callback to extract the configuration given a username.
%%%
%%% Required for the server.
-type auth_keys() :: password | salted_password | client_key | stored_key | server_key.
-type auth_data() :: #{auth_keys() => binary()}.
-type plus_variant() :: undefined | none | binary().
-type nonce() :: #nonce{}.
%%% See `c-nonce' and `s-nonce' at
%%% [https://datatracker.ietf.org/doc/html/rfc5802#section-7].
-type challenge() :: #challenge{}.
-type channel_binding() :: #channel_binding{}.
-type definitions() :: #scram_definitions{}.
-type state() :: #fast_scram_state{}.
-type next_message() :: binary().
-type error_message() :: binary().
%%% See `server-error-message' at
%%% [https://datatracker.ietf.org/doc/html/rfc5802#section-7].
-type final_message() :: binary().
%%% See `client-final-message' and `server-final-message' at
%%% [https://datatracker.ietf.org/doc/html/rfc5802#section-7].

-export_type([
    sha_type/0,
    auth_keys/0,
    auth_data/0,
    challenge/0,
    nonce/0,
    plus_variant/0,
    channel_binding/0,
    retrieve_mechanism/0,
    definitions/0,
    configuration/0,
    next_message/0,
    final_message/0,
    error_message/0,
    state/0
]).

-export([hi/4]).

-export([
    mech_new/1,
    mech_step/2
]).

-export([
    mech_get/2,
    mech_get/3,
    mech_set/3
]).

-export([
    salted_password/4,
    client_key/2,
    stored_key/2,
    client_signature/3,
    client_proof/2,
    server_key/2,
    server_signature/3
]).

-spec mech_new(configuration()) ->
    {ok, state()}
    | {error, term()}.
mech_new(Config) ->
    fast_scram_configuration:mech_new(Config).

-spec mech_get(term(), state()) -> term().
mech_get(Key, #fast_scram_state{data = PD}) ->
    maps:get(Key, PD, undefined).

-spec mech_get(term(), state(), term()) -> term().
mech_get(Key, #fast_scram_state{data = PD}, Default) ->
    maps:get(Key, PD, Default).

-spec mech_set(term(), term(), state()) -> state().
mech_set(Key, Value, #fast_scram_state{data = PD} = State) ->
    State#fast_scram_state{data = PD#{Key => Value}}.

%%% CLIENT STEPS
-spec mech_step(state(), binary()) ->
    {ok, final_message(), state()}
    | {continue, next_message(), state()}
    | {error, error_message(), state()}.
mech_step(
    #fast_scram_state{
        step = 1,
        nonce = Nonce,
        channel_binding = CbConfig,
        data = PrivData
    } = State,
    <<>>
) ->
    {GS2Header, ClientFirstBare} = fast_scram_attributes:client_first_message(
        CbConfig, Nonce, PrivData
    ),
    ClientFirstMessage = <<GS2Header/binary, ClientFirstBare/binary>>,
    NewState = fast_scram_parse_rules:append_to_auth_message_in_state(State, ClientFirstBare),
    {continue, ClientFirstMessage, NewState#fast_scram_state{step = 3}};
mech_step(#fast_scram_state{step = 3} = State, ServerIn) ->
    case parse_server_first_message(ServerIn, State) of
        {ok,
            #fast_scram_state{
                nonce = Nonce,
                challenge = Challenge,
                channel_binding = CbConfig,
                scram_definitions = Scram0,
                data = PrivData
            } = NewState} ->
            ClientFinalNoProof = fast_scram_attributes:client_final_message_without_proof(
                CbConfig, Nonce, PrivData
            ),
            Scram1 = fast_scram_parse_rules:append_to_auth_message(
                Scram0, <<",", ClientFinalNoProof/binary>>
            ),
            Scram2 = fast_scram_definitions:scram_definitions_pipe(Scram1, Challenge, PrivData),
            ClientProof = Scram2#scram_definitions.client_proof,
            ClientFinalMessage = fast_scram_attributes:client_final_message(
                ClientFinalNoProof, ClientProof
            ),
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
%%% An retrieve_mechanism function can add data to the state
%%% For example when the username is needed in order to complete the state data
mech_step(#fast_scram_state{step = 2} = State0, ClientIn) ->
    case parse_client_first_message(ClientIn, State0) of
        {ok, #fast_scram_state{data = PrivData} = State1} ->
            FunRetrieve = maps:get(retrieve_mechanism, PrivData, fun(_) -> #{} end),
            case apply_fun(FunRetrieve, State1) of
                State2 = #fast_scram_state{} ->
                    Nonce = State2#fast_scram_state.nonce,
                    Challenge = State2#fast_scram_state.challenge,
                    Scram0 = State2#fast_scram_state.scram_definitions,
                    ServerFirstMsg = fast_scram_attributes:server_first_message(
                        Nonce, Challenge
                    ),
                    Scram1 = fast_scram_definitions:scram_definitions_pipe(
                        Scram0, Challenge, PrivData
                    ),
                    Scram2 = fast_scram_parse_rules:append_to_auth_message(
                        Scram1, <<",", ServerFirstMsg/binary>>
                    ),
                    NewState1 = State2#fast_scram_state{scram_definitions = Scram2},
                    {continue, ServerFirstMsg, NewState1#fast_scram_state{step = 4}};
                {error, Reason} ->
                    {error, Reason, State1}
            end;
        {error, Reason} ->
            {error, Reason, State0}
    end;
mech_step(#fast_scram_state{step = 4} = State, ClientIn) ->
    case parse_client_final_message(ClientIn, State) of
        {ok,
            #fast_scram_state{
                challenge = Challenge,
                scram_definitions = Scram0,
                data = PrivData
            } = NewState} ->
            GivenClientProof = maps:get(client_proof, PrivData),
            Scram = fast_scram_definitions:scram_definitions_pipe(Scram0, Challenge, PrivData),
            NewState1 = NewState#fast_scram_state{scram_definitions = Scram},
            case fast_scram_definitions:check_proof(Scram, GivenClientProof) of
                ok ->
                    ServerSignature = Scram#scram_definitions.server_signature,
                    ServerLastMessage = fast_scram_attributes:server_final_message(
                        base64:encode(ServerSignature)
                    ),
                    {ok, ServerLastMessage, NewState1#fast_scram_state{step = 6}};
                {error, Reason} ->
                    ServerLastMessage = fast_scram_attributes:server_final_message({error, Reason}),
                    {error, ServerLastMessage, NewState1}
            end;
        {error, Reason} ->
            ServerLastMessage = fast_scram_attributes:server_final_message({error, Reason}),
            {error, ServerLastMessage, State}
    end.

-type username_to_config() :: fun((username()) -> configuration()).
-type username_to_state() :: fun((username(), state()) -> {configuration(), state()}).

-spec apply_fun(Fun, State) -> Result when
    Fun :: username_to_config() | username_to_state(),
    State :: state(),
    Result :: state() | {error, term()}.
apply_fun(Fun, State) when is_function(Fun, 1) ->
    Username = fast_scram:mech_get(username, State),
    Result = Fun(Username),
    apply_result(Result, State);
apply_fun(Fun, State) when is_function(Fun, 2) ->
    Username = fast_scram:mech_get(username, State),
    Result = Fun(Username, State),
    apply_result(Result, State).

apply_result({#{} = Config, #fast_scram_state{} = State}, _) ->
    fast_scram_configuration:mech_append(State, Config);
apply_result(#{} = Config, State) ->
    fast_scram_configuration:mech_append(State, Config);
apply_result({error, Reason}, _) ->
    {error, Reason}.

%%%===================================================================
%%% SCRAM parsing full messages
%%%===================================================================
%  client-first-message =
%        gs2-cbind-flag "," [authzid] "," [reserved-mext ","] username "," nonce ["," extensions]
-spec parse_client_first_message(binary(), state()) -> fast_scram_parse_rules:parse_return().
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
        {UnusedRules, State1 = #fast_scram_state{}} when
            is_list(UnusedRules), length(UnusedRules) == 1
        ->
            ClientFirstMsgBare = extract_client_first_msg_bare_from_first(Chunks, ClientIn),
            State2 = fast_scram_parse_rules:append_to_auth_message_in_state(
                State1, ClientFirstMsgBare
            ),
            {ok, State2};
        {error, Reason} ->
            {error, Reason}
    end.

% server-first-message =
%                   [reserved-mext ","] nonce "," salt ","
%                   iteration-count ["," extensions]
-spec parse_server_first_message(binary(), state()) -> fast_scram_parse_rules:parse_return().
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
        {UnusedRules, State1 = #fast_scram_state{}} when
            is_list(UnusedRules), length(UnusedRules) == 1
        ->
            State2 = fast_scram_parse_rules:append_to_auth_message_in_state(
                State1, <<",", ServerIn/binary>>
            ),
            {ok, State2};
        {error, Reason} ->
            {error, Reason}
    end.

% client-final-message =
%                   channel-binding "," nonce ["," extensions] "," proof
-spec parse_client_final_message(binary(), state()) -> fast_scram_parse_rules:parse_return().
parse_client_final_message(ClientIn, State0) ->
    Rules = [
        fun fast_scram_parse_rules:parse_channel_binding/2,
        fun fast_scram_parse_rules:parse_nonce/2,
        fun fast_scram_parse_rules:parse_extensions/2,
        fun fast_scram_parse_rules:parse_proof/2
    ],
    ClientInList = binary:split(ClientIn, <<",">>, [global]),
    case match_rules(ClientInList, Rules, State0) of
        {UnusedRules, State1 = #fast_scram_state{}} when
            is_list(UnusedRules), length(UnusedRules) == 0
        ->
            ClientFinalNoProof = extract_client_final_no_proof(ClientIn),
            State2 = fast_scram_parse_rules:append_to_auth_message_in_state(
                State1, <<",", ClientFinalNoProof/binary>>
            ),
            {ok, State2};
        {error, Reason} ->
            {error, Reason};
        {_, #fast_scram_state{}} ->
            {error, <<"other-error">>}
    end.

% server-final-message = (server-error / verifier)
%                   ["," extensions]
-spec parse_server_final_message(binary(), state()) -> fast_scram_parse_rules:parse_return().
parse_server_final_message(ServerIn, State0) ->
    Rules = [
        fun fast_scram_parse_rules:parse_server_error_or_verifier/2,
        fun fast_scram_parse_rules:parse_extensions/2
    ],
    ServerInChunks = binary:split(ServerIn, <<",">>, [global]),
    case match_rules(ServerInChunks, Rules, State0) of
        {UnusedRules, State1 = #fast_scram_state{}} when
            is_list(UnusedRules), length(UnusedRules) == 1
        ->
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
        fun
            (_, {error, Reason}) ->
                {error, Reason};
            (Input, {RulesLeft, St}) ->
                apply_rules_until_match(Input, RulesLeft, St)
        end,
        {Rules, State},
        Inputs
    ).

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
%%% Expose definitions from internal modules
%%%===================================================================
-spec salted_password(sha_type(), binary(), binary(), non_neg_integer()) -> binary().
salted_password(Sha, Password, Salt, IterationCount) ->
    fast_scram_definitions:salted_password(Sha, Password, Salt, IterationCount).

-spec client_key(sha_type(), binary()) -> binary().
client_key(Sha, SaltedPassword) ->
    fast_scram_definitions:client_key(Sha, SaltedPassword).

-spec stored_key(sha_type(), binary()) -> binary().
stored_key(Sha, ClientKey) ->
    fast_scram_definitions:stored_key(Sha, ClientKey).

-spec client_signature(sha_type(), binary(), binary()) -> binary().
client_signature(Sha, StoredKey, AuthMessage) ->
    fast_scram_definitions:client_signature(Sha, StoredKey, AuthMessage).

-spec client_proof(binary(), binary()) -> binary().
client_proof(ClientKey, ClientSignature) ->
    fast_scram_definitions:client_proof(ClientKey, ClientSignature).

-spec server_key(sha_type(), binary()) -> binary().
server_key(Sha, SaltedPassword) ->
    fast_scram_definitions:server_key(Sha, SaltedPassword).

-spec server_signature(sha_type(), binary(), binary()) -> binary().
server_signature(Sha, ServerKey, AuthMessage) ->
    fast_scram_definitions:server_signature(Sha, ServerKey, AuthMessage).

%%% @doc See `Hi(str, salt, i)' at [https://datatracker.ietf.org/doc/html/rfc5802#section-2.2]
-spec hi(sha_type(), binary(), binary(), non_neg_integer()) -> binary().
hi(Hash, Password, Salt, IterationCount) ->
    fast_scram_definitions:salted_password(Hash, Password, Salt, IterationCount).
