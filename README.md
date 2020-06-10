fast_scram
=====

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
