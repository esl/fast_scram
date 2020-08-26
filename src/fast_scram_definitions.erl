-module(fast_scram_definitions).

-include("types.hrl").

-export([
         salted_password/4,
         client_key/2,
         stored_key/2,
         client_signature/3,
         client_proof/2,
         server_key/2,
         server_signature/3
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

-spec salted_password(sha_type(), binary(), binary(), non_neg_integer()) -> binary().
salted_password(Sha, Password, Salt, IterationCount)
  when ?is_valid_hash(Sha), is_binary(Password), is_binary(Salt), ?is_positive_integer(IterationCount) ->
    fast_scram:hi(Sha, Password, Salt, IterationCount).

-spec client_key(sha_type(), binary()) -> binary().
client_key(Sha, SaltedPassword)
  when ?is_valid_hash(Sha), is_binary(SaltedPassword) ->
    crypto_hmac(Sha, SaltedPassword, <<"Client Key">>).

-spec stored_key(sha_type(), binary()) -> binary().
stored_key(Sha, ClientKey)
  when ?is_valid_hash(Sha), is_binary(ClientKey) ->
    crypto:hash(Sha, ClientKey).

-spec client_signature(sha_type(), binary(), binary()) -> binary().
client_signature(Sha, StoredKey, AuthMessage)
  when ?is_valid_hash(Sha), is_binary(StoredKey), is_binary(AuthMessage) ->
    crypto_hmac(Sha, StoredKey, AuthMessage).

-spec client_proof(binary(), binary()) -> binary().
client_proof(ClientKey, ClientSignature)
  when is_binary(ClientKey), is_binary(ClientSignature) ->
    crypto:exor(ClientKey, ClientSignature).

-spec server_key(sha_type(), binary()) -> binary().
server_key(Sha, SaltedPassword)
  when ?is_valid_hash(Sha), is_binary(SaltedPassword) ->
    crypto_hmac(Sha, SaltedPassword, <<"Server Key">>).

-spec server_signature(sha_type(), binary(), binary()) -> binary().
server_signature(Sha, ServerKey, AuthMessage)
  when ?is_valid_hash(Sha), is_binary(ServerKey), is_binary(AuthMessage) ->
    crypto_hmac(Sha, ServerKey, AuthMessage).

-if(?OTP_RELEASE >= 22).
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:mac(hmac, Sha, Bin1, Bin2).
-else.
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:hmac(Sha, Bin1, Bin2).
-endif.
