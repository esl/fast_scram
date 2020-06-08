-module(measurements).

-export([
         sample_erlang_pbkdf2/1,
         sample_fast_pbkdf2/1
        ]).

sample_erlang_pbkdf2(#{hash := Hash,
                       strategy := Strategy,
                       iteration_count := IterationCount,
                       sample_size := SampleSize}) ->
    Pass = crypto:strong_rand_bytes(16),
    Salt = crypto:strong_rand_bytes(16),
    Fun  = fun() -> erlang_scram:hi(Hash, Pass, Salt, IterationCount) end,
    stats_sample:sample(Strategy, Fun, SampleSize).

sample_fast_pbkdf2(#{hash := Hash,
                     strategy := Strategy,
                     iteration_count := IterationCount,
                     sample_size := SampleSize}) ->
    Pass = crypto:strong_rand_bytes(16),
    Salt = crypto:strong_rand_bytes(16),
    Fun  = fun() -> fast_scram:fastpbkdf2_hmac_sha(Hash, Pass, Salt, IterationCount) end,
    stats_sample:sample(Strategy, Fun, SampleSize).
