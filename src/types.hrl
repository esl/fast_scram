-include_lib("kernel/include/logger.hrl").

-define(is_positive_integer(N), is_integer(N) andalso N > 0).
-define(is_valid_hash(H), H == sha orelse
        H == sha224 orelse H == sha256 orelse
        H == sha384 orelse H == sha512).

-type sha_type() :: crypto:sha1() | crypto:sha2().

-type username() :: binary().
-type auth_keys() :: password | salted_password | client_key | stored_key | server_key.
-type auth_data() :: #{auth_keys() => binary()}.
-type configuration() :: map().
-type retrieve_mechanism() :: fun((username()) -> configuration())
                            | fun((username(), fast_scram_state()) ->
                                    {configuration(), fast_scram_state()}).

-type parse_return() :: {ok, fast_scram_state()} | {error, binary()}.

-record(nonce, {
          client = <<>> :: binary(),
          server = <<>> :: binary()}
       ).
-type nonce() :: #nonce{}.

-record(challenge, {
          salt = <<>>            :: binary(),
          it_count = 1           :: pos_integer()
         }).
-type challenge() :: #challenge{}.

-record(channel_binding, {
          variant = undefined :: plus_variant(),
          data = <<>> :: binary()
         }).
-type channel_binding() :: #channel_binding{}.
-type plus_variant() :: undefined | none | binary().

-record(scram_definitions, {
          hash_method      :: sha_type(),
          salted_password  = <<>> :: binary(), %Hi(Normalize(password), salt, i),
          client_key       = <<>> :: binary(), %HMAC(SaltedPassword, "Client Key"),
          stored_key       = <<>> :: binary(), %H(ClientKey),
          auth_message     = <<>> :: binary(), %client-first-message-bare + "," +
                                               %server-first-message + "," +
                                               %client-final-message-without-proof
          client_signature = <<>> :: binary(), %HMAC(StoredKey, AuthMessage),
          client_proof     = <<>> :: binary(), %ClientKey XOR ClientSignature,
          server_key       = <<>> :: binary(), %HMAC(SaltedPassword, "Server Key"),
          server_signature = <<>> :: binary()  %HMAC(ServerKey, AuthMessage)
         }).
-type scram_definitions() :: #scram_definitions{}.

-record(fast_scram_state, {
          step :: 1..6, %% Steps 1 & 3 are client, 2 & 4 are server
          nonce = #nonce{} :: nonce(),
          challenge = #challenge{} :: challenge(),
          channel_binding = #channel_binding{} :: channel_binding(),
          scram_definitions = #scram_definitions{} :: scram_definitions(),
          data = #{} :: map()
         }).
-type fast_scram_state() :: #fast_scram_state{}.
