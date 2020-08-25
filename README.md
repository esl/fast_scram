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
The return value is always a 3-tuple, tagged with either `ok` or `error`.
If everything went right, the `ok` tuple returns the message that will be sent to the peer, and the
new state ready for the next step.
If any error arise, the `error` tuple returns an explanation of the error and the state as-it.

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
A ready SCRAM state is build using `fast_scram:mech_new/1`,
which takes a map with the configuration parameters.

The first and most important key is the `entity` key, which takes two values: `client` or `server`.
The next necessary key is the desired `hash_method` method, that is, which of the `SHA` algorithms
will be executed. Can be any of the OTP's `crypto:sha1() | crypto:sha2()`.

Next keys depend on the chosen entity.
If you want to configure a `client` state, then a `username` key is required.
If you want to configure a `server` state, then `it_count` and `salt` are required.

Next, for both cases, an `auth_data` key is required. The value for this key is a map containing the
minimum necessary information for executing a SCRAM algorithm: often just a `password`.
But often, to avoid the challenge penalty, servers and client cache certain keys, considering that a
server often gives the same salt and iteration count for a specific client.
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
The default is `{undefined, <<>>}`, which will set the gs2 flag to none, that is, `<<"n">>`.
If for example a client had channel binding, but saw the server no offering any,
this client should set the flag to `{none, <<>>}`: this will send the gs2 flag as `<<"y">>`.


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
