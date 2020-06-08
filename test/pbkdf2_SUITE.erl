-module(pbkdf2_SUITE).

%% API
-export([all/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2]).

%% test cases
-export([
         erlang_and_nif_are_equivalent_sha1/1,
         erlang_and_nif_are_equivalent_sha224/1,
         erlang_and_nif_are_equivalent_sha256/1,
         erlang_and_nif_are_equivalent_sha384/1,
         erlang_and_nif_are_equivalent_sha512/1,
         realtime_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
     {group, equivalents},
     realtime_test
    ].

groups() ->
    [
     {equivalents, [parallel],
      [
       erlang_and_nif_are_equivalent_sha1,
       erlang_and_nif_are_equivalent_sha224,
       erlang_and_nif_are_equivalent_sha256,
       erlang_and_nif_are_equivalent_sha384,
       erlang_and_nif_are_equivalent_sha512
      ]}
    ].

%%%===================================================================
%%% Overall setup/teardown
%%%===================================================================
init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%%===================================================================
%%% Group specific setup/teardown
%%%===================================================================
init_per_group(_Groupname, Config) ->
    Config.

end_per_group(_Groupname, _Config) ->
    ok.

%%%===================================================================
%%% Testcase specific setup/teardown
%%%===================================================================
init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Individual Test Cases (from groups() definition)
%%%===================================================================

erlang_and_nif_are_equivalent_sha1(_Config) ->
    erlang_and_nif_are_equivalent_(sha, 1).

erlang_and_nif_are_equivalent_sha224(_Config) ->
    erlang_and_nif_are_equivalent_(sha224, 224).

erlang_and_nif_are_equivalent_sha256(_Config) ->
    erlang_and_nif_are_equivalent_(sha256, 256).

erlang_and_nif_are_equivalent_sha384(_Config) ->
    erlang_and_nif_are_equivalent_(sha384, 384).

erlang_and_nif_are_equivalent_sha512(_Config) ->
    erlang_and_nif_are_equivalent_(sha512, 512).

erlang_and_nif_are_equivalent_(Sha, NumberSha) ->
    Prop = ?FORALL({Pass, Salt, Count},
                   {binary(), binary(), range(2,20000)},
                   fast_scram:hi(NumberSha, Pass, Salt, Count)
                       =:= erlang_scram:hi(Sha, Pass, Salt, Count)
                  ),
    ?assert(proper:quickcheck(Prop, [verbose, long_result,
                                     {numtests, 100},
                                     {start_size, 2},
                                     {max_size, 64}])).

-ifdef(STATISTICS).
realtime_test(_Config) ->
    % Allocate two large binaries
    A = crypto:strong_rand_bytes(64),
    B = crypto:strong_rand_bytes(64),
    Fun = fun() ->
                  fast_scram:hi(512, A, B, 10000)
          end,
    #{mean := AverageJitter} = stats_latency:realtime_latency_on_load(Fun, 20, 5000),
    ?assert(AverageJitter < 50).
-else.
realtime_test(_Config) ->
    ok.
-endif.
