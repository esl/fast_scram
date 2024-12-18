%% @private
%% @see fast_scram
-module(fast_scram_parse_rules).

-include("fast_scram.hrl").

-type parse_return() ::
    {ok, fast_scram:state()}
    | {skip_rule, fast_scram:state()}
    | {error, binary()}.
-export_type([parse_return/0]).

-export([
    parse_gs2_cbind_flag/2,
    parse_authzid/2,
    parse_username/2,
    parse_nonce/2,
    parse_salt/2,
    parse_iteration_count/2,
    parse_reserved_mext/2,
    parse_extensions/2,
    parse_proof/2,
    parse_channel_binding/2,
    parse_server_error_or_verifier/2
]).
-export([
    append_to_auth_message/2,
    append_to_auth_message_in_state/2
]).

-spec parse_gs2_cbind_flag(binary(), fast_scram:state()) -> parse_return().
parse_gs2_cbind_flag(<<>>, _State) ->
    {error, <<"no-resources">>};
parse_gs2_cbind_flag(CBind, #fast_scram_state{channel_binding = CbConfig} = State) ->
    % NOTE: if the client doesn't support channel-binding, remove it from the state
    case supported_channel_binding_flag(CBind, CbConfig) of
        #channel_binding{} = NewCbConfig ->
            {ok, State#fast_scram_state{channel_binding = NewCbConfig}};
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_authzid(binary(), fast_scram:state()) -> parse_return().
parse_authzid(<<>>, State) ->
    {ok, State};
parse_authzid(<<"a=", _Rest/binary>>, _State) ->
    {error, <<"authzid-flag-not-supported">>};
parse_authzid(_, _State) ->
    {error, <<"no-resources">>}.

% Mandatory extensions sent by one peer but not understood by the
% other MUST cause authentication failure (the server SHOULD send
% the "extensions-not-supported" server-error-value).
% Unknown optional extensions MUST be ignored upon receipt.
-spec parse_reserved_mext(binary(), fast_scram:state()) -> parse_return().
parse_reserved_mext(<<"m=", _/binary>>, _State) ->
    {error, <<"extensions-not-supported">>};
parse_reserved_mext(_, State) ->
    {skip_rule, State}.

-spec parse_username(binary(), fast_scram:state()) -> parse_return().
parse_username(<<>>, _State) ->
    {error, <<"unknown-user">>};
parse_username(<<"n=", UnescapedUsername/binary>>, #fast_scram_state{data = Data} = State) ->
    case replace_escaped_chars(UnescapedUsername) of
        {ok, EscapedUsername} ->
            case maps:get(username, Data, undefined) of
                CachedName when is_binary(CachedName), CachedName =/= EscapedUsername ->
                    {error, <<"unknown-user">>};
                _ ->
                    NewData = Data#{username => EscapedUsername},
                    {ok, State#fast_scram_state{data = NewData}}
            end;
        E ->
            E
    end;
parse_username(_, _) ->
    {error, <<"other-error">>}.

-spec parse_nonce(binary(), fast_scram:state()) -> parse_return().
parse_nonce(<<>>, _State) ->
    {error, <<"no-resources">>};
parse_nonce(<<"r=", Nonce/binary>>, State) ->
    case update_append_nonce(Nonce, State#fast_scram_state.nonce) of
        #nonce{} = N ->
            {ok, State#fast_scram_state{nonce = N}};
        {error, _} = E ->
            E
    end;
parse_nonce(_, _) ->
    {error, <<"other-error">>}.

-spec parse_salt(binary(), fast_scram:state()) -> parse_return().
parse_salt(<<>>, _State) ->
    {error, <<"no-resources">>};
parse_salt(<<"s=", Salt0/binary>>, State) ->
    Challenge = State#fast_scram_state.challenge,
    case maybe_base64_decode(Salt0) of
        {error, Reason} ->
            {error, Reason};
        Salt ->
            {ok, State#fast_scram_state{challenge = Challenge#challenge{salt = Salt}}}
    end;
parse_salt(_, _) ->
    {error, <<"other-error">>}.

-spec parse_iteration_count(binary(), fast_scram:state()) -> parse_return().
parse_iteration_count(<<>>, _State) ->
    {error, <<"no-resources">>};
parse_iteration_count(<<"i=", ItCount/binary>>, State) ->
    Challenge = State#fast_scram_state.challenge,
    try binary_to_integer(ItCount) of
        It when ?IS_POSITIVE_INTEGER(It) ->
            {ok, State#fast_scram_state{challenge = Challenge#challenge{it_count = It}}}
    catch
        _:_ ->
            {error, <<"invalid-iteration-count">>}
    end;
parse_iteration_count(_, _) ->
    {error, <<"other-error">>}.

-spec parse_extensions(binary(), fast_scram:state()) -> parse_return().
parse_extensions(<<>>, _) ->
    {error, <<"other-error">>};
parse_extensions(<<"m=", _/binary>>, _) ->
    {error, <<"extensions-not-supported">>};
parse_extensions(<<Char:1/binary, _/binary>>, State) ->
    case
        lists:any(
            fun(El) -> Char =:= El end,
            fast_scram_attributes:reserved_scram_codes()
        )
    of
        true -> {skip_rule, State};
        false -> {error, <<"extensions-not-supported">>}
    end.

-spec parse_proof(binary(), fast_scram:state()) -> parse_return().
parse_proof(<<>>, _State) ->
    {error, <<"no-resources">>};
parse_proof(<<"p=">>, _State) ->
    {error, <<"invalid-proof">>};
parse_proof(
    <<"p=", Proof0/binary>>,
    #fast_scram_state{data = Data} = State
) ->
    case maybe_base64_decode(Proof0) of
        {error, Reason} ->
            {error, Reason};
        Proof ->
            {ok, State#fast_scram_state{data = Data#{client_proof => Proof}}}
    end.

-spec parse_channel_binding(binary(), fast_scram:state()) -> parse_return().
parse_channel_binding(<<>>, _State) ->
    {error, <<"no-resources">>};
parse_channel_binding(
    <<"c=", CB/binary>>,
    #fast_scram_state{
        channel_binding = CbConfig,
        data = Data
    } = State
) ->
    case verify_cbind_input(CB, CbConfig, Data) of
        ok ->
            {ok, State};
        {error, Reason} ->
            {error, Reason}
    end;
parse_channel_binding(_, _) ->
    {error, <<"no-resources">>}.

-spec parse_server_error_or_verifier(binary(), fast_scram:state()) -> parse_return().
parse_server_error_or_verifier(
    <<"v=", Verifier/binary>>,
    #fast_scram_state{scram_definitions = #scram_definitions{} = ScramDefs} = State
) ->
    ServerSignature = ScramDefs#scram_definitions.server_signature,
    case maybe_base64_decode(Verifier) of
        ServerSignature ->
            {ok, State};
        {error, Reason} ->
            {error, Reason};
        _ ->
            {error, <<"authentication-failure">>}
    end;
parse_server_error_or_verifier(<<"e=", Error/binary>>, _State) ->
    {error, Error}.

-spec append_to_auth_message(fast_scram:definitions(), binary()) -> fast_scram:definitions().
append_to_auth_message(ScramDefs, NewChunk) ->
    CurrentAuthMessage = ScramDefs#scram_definitions.auth_message,
    NewAppendedAuthMessage = <<CurrentAuthMessage/binary, NewChunk/binary>>,
    ScramDefs#scram_definitions{auth_message = NewAppendedAuthMessage}.

-spec append_to_auth_message_in_state(fast_scram:state(), binary()) -> fast_scram:state().
append_to_auth_message_in_state(State, NewChunk) ->
    ScramDefs0 = State#fast_scram_state.scram_definitions,
    ScramDefs1 = append_to_auth_message(ScramDefs0, NewChunk),
    State#fast_scram_state{scram_definitions = ScramDefs1}.

%%--------------------------------------------------------------------
%% @doc
%% Replace "=2C" with "," and "=3D" with "=". Return invalid-username-encoding
%% if any "=" char is not preceded with either  "2C" or "3D".
%% @end
%%--------------------------------------------------------------------
-spec replace_escaped_chars(binary()) -> {ok, binary()} | {error, binary()}.
replace_escaped_chars(UnescapedUsername) ->
    case binary:match(UnescapedUsername, <<"=">>) of
        nomatch ->
            {ok, UnescapedUsername};
        _ ->
            ReplacedEqual = binary:replace(UnescapedUsername, <<"=3D">>, <<"=">>, [global]),
            EscapedUsername = binary:replace(ReplacedEqual, <<"=2C">>, <<",">>, [global]),
            case binary:match(EscapedUsername, <<"=">>) of
                nomatch ->
                    {ok, EscapedUsername};
                _ ->
                    {error, <<"invalid-username-encoding">>}
            end
    end.

-spec supported_channel_binding_flag(binary(), fast_scram:channel_binding()) ->
    fast_scram:channel_binding() | {error, binary()}.
supported_channel_binding_flag(
    <<"p=", Type/binary>>,
    #channel_binding{variant = Type} = CbConfig
) when Type =/= undefined ->
    CbConfig;
supported_channel_binding_flag(
    <<"p=", _Type/binary>>,
    #channel_binding{variant = OtherType}
) when OtherType =/= undefined ->
    {error, <<"unsupported-channel-binding-type">>};
supported_channel_binding_flag(
    <<"p=", _Type/binary>>,
    #channel_binding{variant = undefined}
) ->
    {error, <<"channel-binding-not-supported">>};
supported_channel_binding_flag(
    <<"y">>,
    #channel_binding{variant = undefined} = CbConfig
) ->
    CbConfig;
supported_channel_binding_flag(
    <<"y">>,
    #channel_binding{variant = Type}
) when Type =/= undefined ->
    {error, <<"server-does-support-channel-binding">>};
supported_channel_binding_flag(
    <<"n">>,
    CbConfig
) ->
    CbConfig#channel_binding{variant = undefined};
supported_channel_binding_flag(_, _) ->
    {error, <<"other-error">>}.

-spec update_append_nonce(binary(), fast_scram:nonce()) -> fast_scram:nonce() | {error, binary()}.
update_append_nonce(ClientNonce, #nonce{client = <<>>} = Nonce) ->
    Nonce#nonce{client = ClientNonce};
update_append_nonce(FullNonce, #nonce{client = Client, server = <<>>} = Nonce) ->
    case binary:longest_common_prefix([FullNonce, Client]) of
        N when N == byte_size(Client) ->
            Nonce#nonce{server = binary:part(FullNonce, {N, byte_size(FullNonce) - N})};
        _ ->
            {error, <<"invalid-nonce">>}
    end;
update_append_nonce(FullNonce, #nonce{client = Client, server = Server} = Nonce) ->
    case FullNonce == <<Client/binary, Server/binary>> of
        true ->
            Nonce;
        _ ->
            {error, <<"invalid-nonce">>}
    end.

-spec verify_cbind_input(binary(), fast_scram:channel_binding(), map()) -> ok | {error, binary()}.
verify_cbind_input(CBindInput, #channel_binding{data = CBindData} = CbConfig, Data) ->
    Constructed = fast_scram_attributes:cbind_input(
        fast_scram_attributes:gs2_header(CbConfig, Data),
        CBindData
    ),
    case Constructed =:= CBindInput of
        true -> ok;
        false -> {error, <<"channel-bindings-dont-match">>}
    end.

maybe_base64_decode(Binary) ->
    try base64:decode(Binary) of
        Decoded -> Decoded
    catch
        error:badarg ->
            {error, <<"invalid-encoding">>}
    end.
