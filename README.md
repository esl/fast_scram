fast_scram
=====

The problem: SCRAM is a challenge response authentication method, that is, it forces the client to
compute a challenge in order to authenticate him. But when the server implementation is slower than
that of an attacker, it makes us vulnerable to DoS by hogging ourselves with computations. We can
see that on CI when registering users in MongooseIM for example.

The solution: is partial. I don't expect to have the fastest implementation, as that would be purely
C code on GPUs, so unfortunately an attacker will pretty much always have better chances there.
_But_ we can make the computation cheap enough for us that other computations —like the load of the
very XMPP session establishment— will be more relevant than this one, and also that other
defence mechanisms like IP blacklisting or traffic shaping, will fire in good time.

Credit where credit is due: The initial algorithm was taken from https://github.com/ctz/fastpbkdf2.
