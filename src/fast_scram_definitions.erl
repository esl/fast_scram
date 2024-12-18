%% @private
%% @see fast_scram
-module(fast_scram_definitions).

-include("fast_scram.hrl").

-export([
    salted_password/4,
    client_key/2,
    stored_key/2,
    client_signature/3,
    client_proof/2,
    server_key/2,
    server_signature/3
]).

-export([
    scram_definitions_pipe/3,
    check_proof/2
]).

%%%===================================================================
%%% SCRAM Definitions
%%%===================================================================
%% SaltedPassword  := Hi(Normalize(password), salt, i)
%% ClientKey       := HMAC(SaltedPassword, "Client Key")
%% StoredKey       := H(ClientKey)
%% AuthMessage     := client-first-message-bare + "," +
%%                    server-first-message + "," +
%%                    client-final-message-without-proof
%% ClientSignature := HMAC(StoredKey, AuthMessage)
%% ClientProof     := ClientKey XOR ClientSignature
%% ServerKey       := HMAC(SaltedPassword, "Server Key")
%% ServerSignature := HMAC(ServerKey, AuthMessage)

-ifdef(WITHOUT_NIFS).
-spec salted_password(fast_scram:sha_type(), binary(), binary(), non_neg_integer()) -> binary().
salted_password(Sha, Password, Salt, IterationCount) when
    ?IS_VALID_HASH(Sha), is_binary(Password), is_binary(Salt), ?IS_POSITIVE_INTEGER(IterationCount)
->
    #{size := KeyLength} = crypto:hash_info(Sha),
    crypto:pbkdf2_hmac(Sha, Password, Salt, IterationCount, KeyLength).
-else.
-spec salted_password(fast_scram:sha_type(), binary(), binary(), non_neg_integer()) -> binary().
salted_password(Sha, Password, Salt, IterationCount) when
    ?IS_VALID_HASH(Sha), is_binary(Password), is_binary(Salt), ?IS_POSITIVE_INTEGER(IterationCount)
->
    fast_pbkdf2:pbkdf2(Sha, Password, Salt, IterationCount).
-endif.

-spec client_key(fast_scram:sha_type(), binary()) -> binary().
client_key(Sha, SaltedPassword) when
    ?IS_VALID_HASH(Sha), is_binary(SaltedPassword)
->
    crypto_hmac(Sha, SaltedPassword, <<"Client Key">>).

-spec stored_key(fast_scram:sha_type(), binary()) -> binary().
stored_key(Sha, ClientKey) when
    ?IS_VALID_HASH(Sha), is_binary(ClientKey)
->
    crypto:hash(Sha, ClientKey).

-spec client_signature(fast_scram:sha_type(), binary(), binary()) -> binary().
client_signature(Sha, StoredKey, AuthMessage) when
    ?IS_VALID_HASH(Sha), is_binary(StoredKey), is_binary(AuthMessage)
->
    crypto_hmac(Sha, StoredKey, AuthMessage).

-spec client_proof(binary(), binary()) -> binary().
client_proof(ClientKey, ClientSignature) when
    is_binary(ClientKey), is_binary(ClientSignature)
->
    crypto:exor(ClientKey, ClientSignature).

-spec server_key(fast_scram:sha_type(), binary()) -> binary().
server_key(Sha, SaltedPassword) when
    ?IS_VALID_HASH(Sha), is_binary(SaltedPassword)
->
    crypto_hmac(Sha, SaltedPassword, <<"Server Key">>).

-spec server_signature(fast_scram:sha_type(), binary(), binary()) -> binary().
server_signature(Sha, ServerKey, AuthMessage) when
    ?IS_VALID_HASH(Sha), is_binary(ServerKey), is_binary(AuthMessage)
->
    crypto_hmac(Sha, ServerKey, AuthMessage).

-ifdef(OTP_RELEASE).
-if(?OTP_RELEASE >= 23).
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:mac(hmac, Sha, Bin1, Bin2).
-else.
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:hmac(Sha, Bin1, Bin2).
-endif.
-else.
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:hmac(Sha, Bin1, Bin2).
-endif.

-spec scram_definitions_pipe(fast_scram:definitions(), fast_scram:challenge(), map()) ->
    fast_scram:definitions().
%% Typical scenario, auth_message is full and we only have the plain password
scram_definitions_pipe(
    #scram_definitions{
        hash_method = HashMethod,
        salted_password = <<>>,
        auth_message = AuthMessage
    } = Scram,
    #challenge{salt = Salt, it_count = ItCount},
    #{password := Password}
) when AuthMessage =/= <<>> ->
    SaltedPassword = salted_password(HashMethod, Password, Salt, ItCount),
    ClientKey = client_key(HashMethod, SaltedPassword),
    StoredKey = stored_key(HashMethod, ClientKey),
    ClientSignature = client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = client_proof(ClientKey, ClientSignature),
    ServerKey = server_key(HashMethod, SaltedPassword),
    ServerSignature = server_signature(HashMethod, ServerKey, AuthMessage),
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
%% We have a cached challenge, we need to verify if it is correct
scram_definitions_pipe(
    #scram_definitions{hash_method = HashMethod, auth_message = AuthMessage} = Scram,
    #challenge{} = GivenChallenge,
    #{challenge := StoredChallenge} = Data
) ->
    case GivenChallenge =:= StoredChallenge of
        % This means that the client has cached the challenge correctly
        true ->
            partial_compute(Scram);
        % Invalid cache, remove all knowledge and try again
        false ->
            ScramWithoutCached = #scram_definitions{
                hash_method = HashMethod, auth_message = AuthMessage
            },
            DataWithoutCached = maps:remove(challenge, Data),
            scram_definitions_pipe(ScramWithoutCached, GivenChallenge, DataWithoutCached)
    end;
scram_definitions_pipe(Scram, _, _) ->
    partial_compute(Scram).

partial_compute(
    #scram_definitions{
        hash_method = HashMethod,
        auth_message = AuthMessage,
        client_key = ClientKey,
        server_key = ServerKey
    } = Scram
) when ClientKey =/= <<>>, ServerKey =/= <<>> ->
    StoredKey = stored_key(HashMethod, ClientKey),
    ClientSignature = client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = client_proof(ClientKey, ClientSignature),
    ServerSignature = server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
        stored_key = StoredKey,
        client_signature = ClientSignature,
        client_proof = ClientProof,
        server_signature = ServerSignature
    };
partial_compute(
    #scram_definitions{
        hash_method = HashMethod,
        auth_message = AuthMessage,
        stored_key = StoredKey,
        server_key = ServerKey
    } = Scram
) when StoredKey =/= <<>>, ServerKey =/= <<>> ->
    ClientSignature = client_signature(HashMethod, StoredKey, AuthMessage),
    ServerSignature = server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
        client_signature = ClientSignature,
        server_signature = ServerSignature
    };
partial_compute(
    #scram_definitions{
        hash_method = HashMethod,
        auth_message = AuthMessage,
        salted_password = SaltedPassword
    } = Scram
) when SaltedPassword =/= <<>> ->
    ClientKey = client_key(HashMethod, SaltedPassword),
    StoredKey = stored_key(HashMethod, ClientKey),
    ClientSignature = client_signature(HashMethod, StoredKey, AuthMessage),
    ClientProof = client_proof(ClientKey, ClientSignature),
    ServerKey = server_key(HashMethod, SaltedPassword),
    ServerSignature = server_signature(HashMethod, ServerKey, AuthMessage),
    Scram#scram_definitions{
        client_key = ClientKey,
        stored_key = StoredKey,
        client_signature = ClientSignature,
        client_proof = ClientProof,
        server_key = ServerKey,
        server_signature = ServerSignature
    };
partial_compute(Scram) ->
    ?LOG_DEBUG(#{what => scram_no_pipe_match}),
    Scram.

-spec check_proof(fast_scram:definitions(), binary()) -> ok | {error, binary()}.
check_proof(#scram_definitions{client_proof = CalculatedClientProof}, GivenClientProof) when
    CalculatedClientProof =:= GivenClientProof
->
    ok;
check_proof(
    #scram_definitions{
        hash_method = HashMethod,
        client_proof = <<>>,
        stored_key = StoredKey,
        client_signature = ClientSignature
    },
    GivenClientProof
) ->
    ClientKey = client_proof(GivenClientProof, ClientSignature),
    CalculatedStoredKey = stored_key(HashMethod, ClientKey),
    case CalculatedStoredKey =:= StoredKey of
        true -> ok;
        _ -> {error, <<"invalid-proof">>}
    end;
check_proof(_, _) ->
    {error, <<"invalid-proof">>}.
