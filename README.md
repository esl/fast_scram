# Fast SCRAM

[![Build Status](https://travis-ci.com/esl/fast_scram.svg?branch=master)](https://travis-ci.org/esl/fast_scram)
[![codecov](https://codecov.io/gh/esl/fast_scram/branch/master/graph/badge.svg)](https://codecov.io/gh/esl/fast_scram)

`fast_scram` is an Erlang implementation of the _Salted Challenge Response Authentication Mechanism_,
where the challenge algorithm is a carefully-optimised NIF, while respecting the latency properties
of the BEAM and the functional aspect of Erlang as a language.

## Building
`fast_scram` is a rebar3-compatible OTP application, that uses the
[port_compiler](https://github.com/blt/port_compiler) for the C part of the code.

Building is as easy as `rebar3 compile`, and using it in your projects as
```erlang
{plugins, [pc]}.
{provider_hooks,
 [{pre,
   [{compile, {pc, compile}},
    {clean, {pc, clean}}]}]}.
{deps,
 [{fast_scram, {git, "https://github.com/esl/fast_scram.git", {branch, "master"}}}]}.
```


## Using
In SCRAM, a `SaltedPassword` is defined as
```
SaltedPassword := Hi(Normalize(password), salt, i)
```
This algorithm is precisely the one that pays the challenge, and it is the one we solve here with
the best performance. Simply do:
```erlang
SaltedPassword = fast_scram:hi(Hash, Password, Salt, IterationCount)
```
where `Hash` is the underlying hash function chosen as described by
```erlang
-type sha_type() :: crypto:sha1() | crypto:sha2().
```

### Full algorithm
If you want to avoid reimplementing SCRAM again and again, you can use the extended API.
The best example is that one of the tests. Given already configured states, the flow is as follows:
```erlang
    %% AUTH
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    %% CHALLENGE
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    %% RESPONSE
    {continue, ClientFinal, ClientState5} = fast_scram:mech_step(ClientState3, ServerFirst),
    %% SUCCESS
    {ok, ServerFinal, ServerFinalState} = fast_scram:mech_step(ServerState4, ClientFinal),
    %% Client successfully accepts the server's verifier
    {ok, ClientFinal, ClientFinalState} = fast_scram:mech_step(ClientState5, ServerFinal).
```

The API is simple: `fast_scram:mech_step/2` takes a SCRAM state, and the last message it received
(in the case of the first step of the client, this is obviously, and necessarily, empty).

The return value is always a 3-tuple, tagged with either `ok`, `continue` or `error`.
The second element is always a binary, and the third is always the scram state.
```erlang
-spec mech_step(fast_scram_state(), binary()) ->
    {ok,       final_message(), fast_scram_state()} |
    {continue,  next_message(), fast_scram_state()} |
    {error,    error_message(), fast_scram_state()}.
```

* `ok` tagged-tuples mean that the algorithm has returned successfully.
  The message will be the last one to send to the peer,
  empty in the case of the client, containing the server verifier for the server.
  The state will not be needed anymore, so it can be ignored.
* `continue` means that the algorithm is not done yet. The message is what needs to be send to the
  peer, by whatever means the protocol chooses (encoded in a major packet through some network
  protocol, etc). The new state is the one that should be plugged into the next step,
  when the peer has answered.
* `error` means that the algorithm is over, unsuccessfully, where the message contains some
  explanation. The state might include parsed data or be return as it was.

How messages are delivered to peers is part of the protocol within which SCRAM is embedded:
for example, in XMPP, messages are delivered as special stanzas with the SCRAM payload encoded in
`base64`. So an XMPP client would do, for example, using [exml][exml]
```erlang
    {continue, Message, NewState} = fast_scram:mech_step(State, <<>>),
    Contents = #xmlcdata{content = base64:encode(Message)},
    Stanza = #xmlel{name = <<"auth">>,
                    attrs = [{<<"xmlns">>, <<"urn:ietf:params:xml:ns:xmpp-sasl">>},
                             {<<"mechanism">>, <<"SCRAM-SHA-1">>}],
                    children = [Contents]},
    %% send stanza
```

### Configuration
This is the part that requires some knowledge of the SCRAM protocol.
A ready SCRAM state is built using `fast_scram:mech_new/1`,
which takes a map with the configuration parameters.

Example configurations are, for the client:
```erlang
    #{entity => client,
      hash_method => sha,
      username => <<"user">>,
      auth_data => #{password => <<"somesupersafepassword">>}}
```

And for a server:
```erlang
    #{entity => server,
      hash_method => sha,
      nonce => <<"3rfcNHYJY1ZVvWVs7j">>,
      retrieve_mechanism => fun(Username) -> MoreConfig end}
```

The first and most important key is the `entity` key,
which takes two values: `client` or `server`.
The next necessary key is the negotiated `hash_method`,
that is, which of the `SHA` algorithms will be executed.
Can be any of the OTP's `crypto:sha1() | crypto:sha2()`.

Next keys depend on the chosen entity.
If you want to configure a `client` state, then a `username` key is required.
If you want to configure a `server` state, then `retrieve_mechanism` is required.

Next, for both cases, an `auth_data` key is required. The value for this key is a map containing the
minimum necessary information for executing a SCRAM algorithm: often just a `password`.
But often, to avoid the challenge penalty, servers and client cache certain keys,
considering that a server often gives the same salt and iteration count for a specific client.
So we can instead cache `salted_password`, or a pair `stored_key`-`server_key`,
or a pair `client_key`-`server_key`. All these pairs can be given with a `password` as a fallback,
if the algorithm was to need recalculation.

If the client is being given any cached configuration, it will simply attempt that data regardless
of the challenge that the server requests from him. If verification was desired instead of failing,
the main config map can take keys `cached_it_count` and `cached_salt`, and these will be verified
against the challenge requested by the server: if it matches, the cached data will be used. If it
doesn't, all data will be recalculated using the `password` key in the `auth_data` map, provided it
is available.

Channel binding specification can also be given by `channel_binding => {Type, Data}`,
where `Type` is the channel binding name, and `Data` is its associated payload.
The default is `{undefined, <<>>}`, which will set the gs2 flag to no binding, that is, `<<"n">>`.
If for example a client had channel binding, but saw the server not offering any,
this client should set the flag to `{none, <<>>}`: this will send the gs2 flag as `<<"y">>`.

### Server retrieval of the client's data

SCRAM requires that the server retrieves the user's data with the username as exactly given
in the client's first message. To configure this, a `retrieve_mechanism` key is required,
whose value is a function of the type:

```erlang
-type retrieve_mechanism() :: fun((username()) -> configuration())
                            | fun((username(), fast_scram_state()) ->
                                    {configuration(), fast_scram_state()}).
```

That is, a function object that:
* Takes a username and returns more configuration to append to the state
* Takes a username and the current state, and returns a pair of the extended
configuration and a possibly new state.

See examples below.

#### `fun((username()) -> configuration())`

```erlang
    Fun = fun(Username) ->
              %% Get scram data for this user from the database
              ...
              %%% {StoredKey, ServerKey, Salt, ItCount} ->
              ...
              #{salt => Salt,
                it_count => ItCount,
                auth_data => #{stored_key => StoredKey,
                               server_key => ServerKey}}
          end,
    {ok, State} = fast_scram:mech_new(
                        #{entity => server, hash_method => Sha, retrieve_mechanism => Fun}).
```

#### `fun((username(), fast_scram_state()) -> {configuration(), fast_scram_state()}).`

```erlang
    Fun = fun(Username, State0) ->
              %% Get scram data for this user from the database
              ...
              %%% {StoredKey, ServerKey, Salt, ItCount} ->
              ...
              Config = #{salt => Salt,
                        it_count => ItCount,
                        auth_data => #{
                            stored_key => StoredKey,
                            server_key => ServerKey}}

              %% Custom data can also be stored in the state to be extracted later
              State1 = fast_scram:mech_set(some_key, SomeData, State0),
              {Config, State1}
          end,
    {ok, State} = fast_scram:mech_new(
                        #{entity => server, hash_method => Sha, retrieve_mechanism => Fun}).
```

## Performance

### The problem
SCRAM is a challenge-response authentication method, that is, it forces the client to compute a
challenge in order to authenticate him. But when the server implementation is slower than that
of an attacker, it makes the server vulnerable to DoS by hogging itself with computations.
We could see that on the CI and load-testing pipelines of [MongooseIM][MIM] for example.

### The solution
Is partial. We don't expect to have the fastest implementation, as that would be purely C code on
GPUs, so unfortunately an attacker will pretty much always have better chances there.  _But_ we can
make the computation cheap enough for us that other computations —like the load of a session
establishment— will be more relevant than that of the challenge; and also that other defence
mechanisms like IP blacklisting or traffic shaping, will fire in good time.

### The outcome
On average it's 10x faster on the machines I've tested it (you can compare using the provided module
in `./benchmarks/measurements.erl`), but while the erlang implementation consumes memory linearly to
the iteration count (1M it count with 120 clients quickly allocated 7GB of RAM, and 1M is common for
password managers for example), the NIF implementation does not allocate any more memory. Also, the
NIFS spend all of their time in user level alone, while the erlang one jumps to system calls in
around ~2% of the time (I'd guess due to some heavy allocation and garbage collection patterns).


## Credit where credit is due
The initial algorithm and optimisations were taken from Joseph Birr-Pixton's
[fastpbkdf2](https://github.com/ctz/fastpbkdf2)'s repository.

## Read more:
* SCRAM: [RFC5802](https://tools.ietf.org/html/rfc5802)
* SCRAM-SHA-256 update: [RFC7677](https://tools.ietf.org/html/rfc7677)
* Password-Based Cryptography Specification (PBKDF2): [RFC8018](https://tools.ietf.org/html/rfc8018)
* HMAC: [RFC2104]( https://tools.ietf.org/html/rfc2104)
* SHAs and HMAC-SHA: [RFC6234](https://tools.ietf.org/html/rfc6234)

[MIM]: https://github.com/esl/MongooseIM
[exml]: https://github.com/esl/exml/
