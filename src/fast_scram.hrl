-include_lib("kernel/include/logger.hrl").

-define(IS_POSITIVE_INTEGER(N), is_integer(N) andalso N > 0).
-define(IS_VALID_HASH(H),
    H =:= sha orelse
        H =:= sha224 orelse H =:= sha256 orelse
        H =:= sha384 orelse H =:= sha512 orelse
        H =:= sha3_224 orelse H =:= sha3_256 orelse
        H =:= sha3_384 orelse H =:= sha3_512
).

-record(nonce, {
    client = <<>> :: binary(),
    server = <<>> :: binary()
}).

-record(challenge, {
    salt = <<>> :: binary(),
    it_count = 1 :: pos_integer()
}).

-record(channel_binding, {
    variant = undefined :: fast_scram:plus_variant(),
    data = <<>> :: binary()
}).

-record(scram_definitions, {
    hash_method :: fast_scram:sha_type(),
    %Hi(Normalize(password), salt, i),
    salted_password = <<>> :: binary(),
    %HMAC(SaltedPassword, "Client Key"),
    client_key = <<>> :: binary(),
    %H(ClientKey),
    stored_key = <<>> :: binary(),
    %client-first-message-bare + "," +
    auth_message = <<>> :: binary(),
    %server-first-message + "," +
    %client-final-message-without-proof

    %HMAC(StoredKey, AuthMessage),
    client_signature = <<>> :: binary(),
    %ClientKey XOR ClientSignature,
    client_proof = <<>> :: binary(),
    %HMAC(SaltedPassword, "Server Key"),
    server_key = <<>> :: binary(),
    %HMAC(ServerKey, AuthMessage)
    server_signature = <<>> :: binary()
}).

-record(fast_scram_state, {
    %% Steps 1 & 3 are client, 2 & 4 are server
    step :: 1..6,
    nonce = #nonce{} :: fast_scram:nonce(),
    challenge = #challenge{} :: fast_scram:challenge(),
    channel_binding = #channel_binding{} :: fast_scram:channel_binding(),
    scram_definitions = #scram_definitions{} :: fast_scram:definitions(),
    data = #{} :: map()
}).
