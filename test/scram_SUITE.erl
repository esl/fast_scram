-module(scram_SUITE).

-include("src/fast_scram.hrl").

%% API
-export([all/0, groups/0]).

%% test cases
-export([
    regular_scram_authentication_example_from_the_rfc/1,
    regular_scram_authentication/1,
    wrong_configuration_key/1,
    configuration_client_sends_wrong_username/1,
    configuration_cached_keys_works_easily/0,
    configuration_cached_keys_works_easily/1,
    configuration_cached_keys_works_easily_v2/0,
    configuration_cached_keys_works_easily_v2/1,
    configuration_cached_wrong_simply_recalculates/0,
    configuration_cached_wrong_simply_recalculates/1,
    configuration_cached_wrong_without_password_fails/0,
    configuration_cached_wrong_without_password_fails/1,
    verification_name_escapes_values_correctly/1,
    verification_name_does_not_escape_values_correctly/1,
    authentication_server_last_message_is_an_error/1,
    authentication_server_rejects_the_proof/1,
    authentication_server_rejects_invalid_encoded_proof/1,
    authentication_client_rejects_the_signature/1,
    nonce_client_receives_invalid/1,
    nonce_server_finds_non_matching/1,
    channel_not_advertise_but_client_could_is_ok/1,
    channel_binding_client_did_not_see_available_plus/1,
    channel_server_offers_but_client_does_not_take_is_ok/1,
    channel_type_does_not_match/1,
    channel_type_matches_but_data_does_not/1,
    channel_is_not_supported_by_the_server/1,
    missing_username/1,
    missing_authzid/1,
    missing_gs2/1,
    missing_gs2_info/1,
    missing_nonce/1,
    missing_salt/1,
    missing_it_count/1,
    missing_proof/1,
    missing_proof_info/1,
    missing_channel_binding/1,
    missing_channel_binding_info/1,
    wrong_flag_username/1,
    wrong_flag_g2s/1,
    wrong_flag_nonce/1,
    wrong_flag_salt/1,
    wrong_flag_it_count/1,
    wrong_it_count/1,
    too_much_input/1,
    not_supported_authzid/1,
    not_supported_mext/1,
    not_supported_extension/1
]).

-include_lib("stdlib/include/assert.hrl").

all() ->
    [
        {group, verifications},
        {group, authentication},
        {group, nonce},
        {group, channel},
        {group, missing_flags},
        {group, wrong_input},
        {group, not_supported}
    ].

groups() ->
    [
        {verifications, [parallel], [
            regular_scram_authentication_example_from_the_rfc,
            regular_scram_authentication,
            wrong_configuration_key,
            verification_name_escapes_values_correctly,
            verification_name_does_not_escape_values_correctly,
            configuration_client_sends_wrong_username,
            configuration_cached_keys_works_easily,
            configuration_cached_keys_works_easily_v2,
            configuration_cached_wrong_simply_recalculates,
            configuration_cached_wrong_without_password_fails
        ]},
        {authentication, [parallel], [
            authentication_server_last_message_is_an_error,
            authentication_server_rejects_the_proof,
            authentication_server_rejects_invalid_encoded_proof,
            authentication_client_rejects_the_signature
        ]},
        {nonce, [parallel], [
            nonce_client_receives_invalid,
            nonce_server_finds_non_matching
        ]},
        {channel, [parallel], [
            channel_not_advertise_but_client_could_is_ok,
            channel_binding_client_did_not_see_available_plus,
            channel_server_offers_but_client_does_not_take_is_ok,
            channel_type_does_not_match,
            channel_type_matches_but_data_does_not,
            channel_is_not_supported_by_the_server
        ]},
        {missing_flags, [parallel], [
            missing_username,
            missing_authzid,
            missing_gs2,
            missing_gs2_info,
            missing_nonce,
            missing_salt,
            missing_it_count,
            missing_proof,
            missing_proof_info,
            missing_channel_binding,
            missing_channel_binding_info
        ]},
        {wrong_input, [], [
            wrong_flag_username,
            wrong_flag_g2s,
            wrong_flag_nonce,
            wrong_flag_salt,
            wrong_flag_it_count,
            wrong_it_count,
            too_much_input
        ]},
        {not_supported, [parallel], [
            not_supported_authzid,
            not_supported_mext,
            not_supported_extension
        ]}
    ].

%%%===================================================================
%%% Individual Test Cases (from groups() definition)
%%%===================================================================
regular_scram_authentication_example_from_the_rfc(_Config) ->
    %% Client and Server have matching configurations
    ClientState1 = typical_scram_configuration(client),
    ServerState2 = typical_scram_configuration(server),
    %% AUTH
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ?assertEqual(client_first(), ClientFirst),
    %% CHALLENGE
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    ?assertEqual(server_first(), ServerFirst),
    %% RESPONSE
    {continue, ClientFinal, ClientState5} = fast_scram:mech_step(ClientState3, ServerFirst),
    ?assertEqual(client_final(), ClientFinal),
    %% SUCCESS
    {ok, ServerFinal, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    ?assertEqual(server_final(), ServerFinal),
    %% Client successfully accepts the server's verifier
    {ok, _Final, _ClientState7} = fast_scram:mech_step(ClientState5, ServerFinal).

regular_scram_authentication(_Config) ->
    Password = base64:encode(crypto:strong_rand_bytes(8 + rand:uniform(8))),
    {ok, ClientState1} = fast_scram:mech_new(#{
        entity => client,
        hash_method => sha256,
        username => <<"user">>,
        auth_data => #{password => Password}
    }),
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha256,
            username => <<"user">>,
            retrieve_mechanism =>
                fun(U, S) -> retrieve_mechanism(U, #{password => Password}, S) end
        }
    ),
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    {continue, ClientFinal, ClientState5} = fast_scram:mech_step(ClientState3, ServerFirst),
    {ok, ServerFinal, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    {ok, _Final, _ClientState7} = fast_scram:mech_step(ClientState5, ServerFinal).

wrong_configuration_key(_Config) ->
    {error, wrong_key, bad_key} = fast_scram:mech_new(
        #{
            entity => client,
            hash_method => sha256,
            username => <<"user">>,
            bad_key => any_value,
            auth_data => #{password => <<"pencil">>}
        }
    ).

configuration_cached_keys_works_easily() ->
    [{timetrap, {seconds, 1}}].

configuration_cached_keys_works_easily(_Config) ->
    Cached = cached_heavy_scram_definitions(),
    {ok, ClientState1} = fast_scram:mech_new(
        #{
            entity => client,
            hash_method => sha,
            username => <<"user">>,
            cached_challenge => {base64:decode(<<"QSXCR+Q6sek8bf92">>), 409600000},
            auth_data => #{salted_password => Cached#scram_definitions.salted_password}
        }
    ),
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 409600000,
                        auth_data => #{
                            stored_key => Cached#scram_definitions.stored_key,
                            server_key => Cached#scram_definitions.server_key
                        }
                    }
                end
        }
    ),
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    {continue, ClientFinal, ClientState5} = fast_scram:mech_step(ClientState3, ServerFirst),
    {ok, ServerFinal, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    {ok, _Final, _ClientState7} = fast_scram:mech_step(ClientState5, ServerFinal).

configuration_cached_keys_works_easily_v2() ->
    [{timetrap, {seconds, 1}}].

configuration_cached_keys_works_easily_v2(_Config) ->
    Cached = cached_heavy_scram_definitions(),
    {ok, ClientState1} = fast_scram:mech_new(
        #{
            entity => client,
            hash_method => sha,
            username => <<"user">>,
            cached_challenge => {409600000, base64:decode(<<"QSXCR+Q6sek8bf92">>)},
            auth_data => #{
                client_key => Cached#scram_definitions.client_key,
                server_key => Cached#scram_definitions.server_key
            }
        }
    ),
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 409600000,
                        auth_data => #{
                            salted_password =>
                                Cached#scram_definitions.salted_password
                        }
                    }
                end
        }
    ),
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    {continue, ClientFinal, ClientState5} = fast_scram:mech_step(ClientState3, ServerFirst),
    {ok, ServerFinal, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    {ok, _Final, _ClientState7} = fast_scram:mech_step(ClientState5, ServerFinal).

configuration_cached_wrong_simply_recalculates() ->
    [{timetrap, {seconds, 1}}].

configuration_cached_wrong_simply_recalculates(_Config) ->
    CachedRegular = cached_regular_scram_refinitions(),
    CachedHeavy = cached_heavy_scram_definitions(),
    {ok, ClientState1} = fast_scram:mech_new(
        #{
            entity => client,
            hash_method => sha,
            username => <<"user">>,
            cached_challenge => {409600000, base64:decode(<<"QSXCR+Q6sek8bf92">>)},
            auth_data => #{
                password => <<"pencil">>,
                salted_password => CachedHeavy#scram_definitions.salted_password
            }
        }
    ),
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{
                            password => <<"pencil">>,
                            stored_key => CachedRegular#scram_definitions.stored_key,
                            server_key =>
                                CachedRegular#scram_definitions.server_key
                        }
                    }
                end
        }
    ),
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    {continue, ClientFinal, ClientState5} = fast_scram:mech_step(ClientState3, ServerFirst),
    {ok, ServerFinal, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    {ok, _Final, _ClientState7} = fast_scram:mech_step(ClientState5, ServerFinal).

configuration_cached_wrong_without_password_fails() ->
    [{timetrap, {seconds, 1}}].

configuration_cached_wrong_without_password_fails(_Config) ->
    CachedRegular = cached_regular_scram_refinitions(),
    CachedHeavy = cached_heavy_scram_definitions(),
    {ok, ClientState1} = fast_scram:mech_new(
        #{
            entity => client,
            hash_method => sha,
            username => <<"user">>,
            cached_challenge => {409600000, base64:decode(<<"QSXCR+Q6sek8bf92">>)},
            auth_data => #{
                salted_password => CachedHeavy#scram_definitions.salted_password
            }
        }
    ),
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{
                            password => <<"pencil">>,
                            stored_key => CachedRegular#scram_definitions.stored_key,
                            server_key =>
                                CachedRegular#scram_definitions.server_key
                        }
                    }
                end
        }
    ),
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    {continue, ClientFinal, _} = fast_scram:mech_step(ClientState3, ServerFirst),
    {error, Reason, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    ?assertEqual(<<"e=invalid-proof">>, Reason).

authentication_server_rejects_the_proof(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    WrongProof =
        <<"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,", "p=",
            (base64:encode(<<"wrong_proof">>))/binary>>,
    {error, Reason, _} = fast_scram:mech_step(ServerState4, WrongProof),
    ?assertEqual(<<"e=invalid-proof">>, Reason).

authentication_server_rejects_invalid_encoded_proof(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    WrongProof = <<"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,", "p=wrong_proof">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState4, WrongProof),
    ?assertEqual(<<"e=invalid-encoding">>, Reason).

authentication_client_rejects_the_signature(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, _, ClientState5} = fast_scram:mech_step(ClientState3, server_first()),
    WrongSignature = <<"v=", (base64:encode(<<"wrong_signature">>))/binary>>,
    {error, Reason, _} = fast_scram:mech_step(ClientState5, WrongSignature),
    ?assertEqual(<<"authentication-failure">>, Reason).

authentication_server_last_message_is_an_error(_Config) ->
    ClientState = typical_scram_configuration(client),
    {error, Reason, _} = fast_scram:mech_step(
        ClientState#fast_scram_state{step = 5}, <<"e=invalid">>
    ),
    ?assertEqual(<<"invalid">>, Reason).

configuration_client_sends_wrong_username(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    ServerState0 = typical_scram_configuration(server),
    ServerState2 = ServerState0#fast_scram_state{
        data = #{username => <<"not-user">>, password => <<"pencil">>}
    },
    {continue, ClientFirst, _} = fast_scram:mech_step(ClientState1, <<>>),
    {error, Reason, _} = fast_scram:mech_step(ServerState2, ClientFirst),
    ?assertEqual(<<"unknown-user">>, Reason).

verification_name_escapes_values_correctly(_Config) ->
    ServerState0 = #fast_scram_state{data = Data} = typical_scram_configuration(server),
    ServerState2 = ServerState0#fast_scram_state{
        data = Data#{username => <<"u,ser">>, password => <<"pencil">>}
    },
    Username = <<"n,,n=u=2Cser,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {NextStep, _, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(continue, NextStep).

verification_name_does_not_escape_values_correctly(_Config) ->
    ServerState0 = typical_scram_configuration(server),
    ServerState2 = ServerState0#fast_scram_state{
        data = #{username => <<"u,ser">>, password => <<"pencil">>}
    },
    Username = <<"n,,n=u=ser,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"invalid-username-encoding">>, Reason).

%% The client MUST verify that the initial part of the nonce used in subsequent messages
%% is the same as the nonce it initially specified
nonce_client_receives_invalid(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWrongNonce = <<"r=clientreceiveswrongnonce3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWrongNonce),
    ?assertEqual(<<"invalid-nonce">>, Reason).

%% The server MUST verify that the nonce sent by the client in the second message
%% is the same as the one sent by the server in its first message.
nonce_server_finds_non_matching(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    WrongNonce =
        <<"c=biws,r=bad_nonce_FgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState4, WrongNonce),
    ?assertEqual(<<"e=invalid-nonce">>, Reason).

%% If the flag is set to "y" and the server supports channel binding,
%% the server MUST fail authentication.
%% This is because if the client sets the channel binding flag to "y",
%% then the client must have believed that the server did not support channel binding
%% -- if the server did in fact support channel binding,
%% then this is an indication that there has been a downgrade attack
%% (e.g., an attacker changed the server’s mechanism list to exclude the -PLUS
%% suffixed SCRAM mechanism name(s)).
channel_binding_client_did_not_see_available_plus(_Config) ->
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            channel_binding => {<<"tls-unique">>, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{
                            password => <<"pencil">>
                        }
                    }
                end
        }
    ),
    YesGS2Flag = <<"y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, YesGS2Flag),
    ?assertEqual(<<"server-does-support-channel-binding">>, Reason).

channel_server_offers_but_client_does_not_take_is_ok(_Config) ->
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            channel_binding => {<<"tls-unique">>, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{password => <<"pencil">>}
                    }
                end
        }
    ),
    YesGS2Flag = <<"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {continue, _, _} = fast_scram:mech_step(ServerState2, YesGS2Flag).

channel_not_advertise_but_client_could_is_ok(_Config) ->
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{password => <<"pencil">>}
                    }
                end
        }
    ),
    YesGS2Flag = <<"y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {continue, _, _} = fast_scram:mech_step(ServerState2, YesGS2Flag).

%% If the channel binding flag was "p" and the server does not support
%% the indicated channel binding type, then the server MUST fail authentication.
channel_type_does_not_match(_Config) ->
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            channel_binding => {<<"some_server_type">>, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{password => <<"pencil">>}
                    }
                end
        }
    ),
    ClientFirst = <<"p=some_client_type,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, ClientFirst),
    ?assertEqual(<<"unsupported-channel-binding-type">>, Reason).

channel_type_matches_but_data_does_not(_Config) ->
    {ok, ClientState1} = fast_scram:mech_new(
        #{
            entity => client,
            hash_method => sha,
            username => <<"user">>,
            channel_binding => {<<"tls-unique">>, <<1, 2, 3, 4, 5, 6, 7, 8>>},
            auth_data => #{password => <<"pencil">>}
        }
    ),
    {ok, ServerState2} = fast_scram:mech_new(
        #{
            entity => server,
            hash_method => sha,
            channel_binding => {<<"tls-unique">>, <<2, 2, 3, 4, 5, 6, 7, 8>>},
            retrieve_mechanism =>
                fun(_) ->
                    #{
                        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
                        it_count => 4096,
                        auth_data => #{password => <<"pencil">>}
                    }
                end
        }
    ),
    {continue, ClientFirst, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    {continue, ServerFirst, ServerState4} = fast_scram:mech_step(ServerState2, ClientFirst),
    {continue, ClientFinal, _} = fast_scram:mech_step(ClientState3, ServerFirst),
    {error, Reason, _} = fast_scram:mech_step(ServerState4, ClientFinal),
    ?assertEqual(<<"e=channel-bindings-dont-match">>, Reason).

channel_is_not_supported_by_the_server(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    ClientFirst = <<"p=tls-unique,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, ClientFirst),
    ?assertEqual(<<"channel-binding-not-supported">>, Reason).

missing_username(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"n,,,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"unknown-user">>, Reason).
missing_authzid(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"n,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"no-resources">>, Reason).
missing_gs2_info(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<",,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"no-resources">>, Reason).
missing_gs2(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<",n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"no-resources">>, Reason).
missing_nonce(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"n,,n=user,">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"no-resources">>, Reason).
missing_salt(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWrongNonce = <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,,i=4096">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWrongNonce),
    ?assertEqual(<<"no-resources">>, Reason).
missing_it_count(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWrongNonce = <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWrongNonce),
    ?assertEqual(<<"no-resources">>, Reason).
missing_proof_info(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    WrongProof = <<"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,">>,
    {error, NoResources, _} = fast_scram:mech_step(ServerState4, WrongProof),
    ?assertEqual(<<"e=other-error">>, NoResources),
    EmptyProof = <<"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=">>,
    {error, InvalidProof, _} = fast_scram:mech_step(ServerState4, EmptyProof),
    ?assertEqual(<<"e=invalid-proof">>, InvalidProof).
missing_proof(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    WrongProof = <<"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState4, WrongProof),
    ?assertEqual(<<"e=other-error">>, Reason).
missing_channel_binding_info(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    MissingCB = <<",r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState4, MissingCB),
    ?assertEqual(<<"e=no-resources">>, Reason).
missing_channel_binding(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    {continue, _, ServerState4} = fast_scram:mech_step(ServerState2, client_first()),
    MissingCB = <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState4, MissingCB),
    ?assertEqual(<<"e=no-resources">>, Reason).

wrong_flag_username(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"n,,wrong,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"other-error">>, Reason).
wrong_flag_g2s(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"wrong,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"other-error">>, Reason).
wrong_flag_nonce(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"n,,n=user,wrong">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"other-error">>, Reason).
wrong_flag_salt(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWrongNonce = <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,wrong,i=4096">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWrongNonce),
    ?assertEqual(<<"other-error">>, Reason).
wrong_flag_it_count(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWrongItCount =
        <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,wrong">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWrongItCount),
    ?assertEqual(<<"other-error">>, Reason).
wrong_it_count(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWrongItCount =
        <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=wrong">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWrongItCount),
    ?assertEqual(<<"invalid-iteration-count">>, Reason).
too_much_input(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    Username = <<"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=toomuch">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, Username),
    ?assertEqual(<<"error-too-much-input">>, Reason).

not_supported_authzid(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    ClientFirst = <<"n,a=other_user,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, ClientFirst),
    ?assertEqual(<<"authzid-flag-not-supported">>, Reason).
not_supported_mext(_Config) ->
    ClientState1 = typical_scram_configuration(client),
    {continue, _, ClientState3} = fast_scram:mech_step(ClientState1, <<>>),
    ServerWithMext =
        <<"m=mext,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096">>,
    {error, Reason, _} = fast_scram:mech_step(ClientState3, ServerWithMext),
    ?assertEqual(<<"extensions-not-supported">>, Reason).
not_supported_extension(_Config) ->
    ServerState2 = typical_scram_configuration(server),
    ClientFirst1 = <<"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL,t=extension">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, ClientFirst1),
    ?assertEqual(<<"extensions-not-supported">>, Reason),
    ClientFirst2 = <<"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL,m=extension">>,
    {error, Reason, _} = fast_scram:mech_step(ServerState2, ClientFirst2),
    ?assertEqual(<<"extensions-not-supported">>, Reason).

%%%===================================================================
%%% Helper functions
%%%===================================================================

typical_scram_configuration(Entity) ->
    typical_scram_configuration(Entity, #{password => <<"pencil">>}, #{}).

typical_scram_configuration(client, AuthData, Other) ->
    Config0 = #{
        entity => client,
        hash_method => sha,
        username => <<"user">>,
        nonce => <<"fyko+d2lbbFgONRv9qkxdawL">>,
        auth_data => AuthData
    },
    Config1 = maps:merge(Config0, Other),
    {ok, St} = fast_scram:mech_new(Config1),
    St;
typical_scram_configuration(server, AuthData, Other) ->
    Config0 = #{
        entity => server,
        hash_method => sha,
        nonce => <<"3rfcNHYJY1ZVvWVs7j">>,
        retrieve_mechanism => fun(U, S) -> retrieve_mechanism(U, AuthData, S) end
    },
    Config1 = maps:merge(Config0, Other),
    {ok, St} = fast_scram:mech_new(Config1),
    St.

retrieve_mechanism(_, AuthData, S) ->
    X = #{
        salt => base64:decode(<<"QSXCR+Q6sek8bf92">>),
        it_count => 4096,
        auth_data => AuthData
    },
    {X, S}.

client_first() -> <<"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL">>.
server_first() -> <<"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096">>.
client_final() ->
    <<"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=">>.
server_final() -> <<"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=">>.

%%% Precalculated with an iteration cout of 4096
cached_regular_scram_refinitions() ->
    #scram_definitions{
        hash_method = sha,
        salted_password =
            <<29, 150, 238, 58, 82, 155, 90, 95, 158, 71, 192, 31, 34, 154, 44, 184, 166, 225, 95,
                125>>,
        client_key =
            <<226, 52, 196, 123, 246, 195, 102, 150, 221, 109, 133, 43, 153, 170, 162, 186, 38, 85,
                87, 40>>,
        stored_key =
            <<233, 217, 70, 96, 195, 157, 101, 195, 143, 186, 217, 28, 53, 143, 20, 218, 14, 239,
                43, 214>>,
        auth_message =
            <<"n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j">>,
        client_signature =
            <<93, 113, 56, 196, 134, 176, 191, 171, 223, 73, 227, 226, 218, 139, 214, 229, 199, 157,
                182, 19>>,
        client_proof =
            <<191, 69, 252, 191, 112, 115, 217, 61, 2, 36, 102, 201, 67, 33, 116, 95, 225, 200, 225,
                59>>,
        server_key =
            <<15, 224, 146, 88, 179, 172, 133, 43, 165, 2, 204, 98, 186, 144, 62, 170, 205, 191,
                125, 49>>,
        server_signature =
            <<174, 97, 125, 166, 165, 124, 75, 187, 46, 2, 134, 86, 141, 174, 29, 37, 25, 5, 176,
                164>>
    }.

%%% This was calculated for the same parameters than as above,
%%% except that the iteration count is 409600000, so it would take a long time
cached_heavy_scram_definitions() ->
    #scram_definitions{
        hash_method = sha,
        salted_password =
            <<88, 214, 221, 58, 163, 214, 103, 20, 235, 222, 209, 209, 41, 158, 166, 159, 61, 23,
                116, 62>>,
        client_key =
            <<30, 240, 57, 94, 35, 56, 109, 230, 129, 154, 73, 94, 142, 182, 50, 156, 78, 128, 171,
                29>>,
        stored_key =
            <<31, 45, 16, 146, 4, 98, 92, 24, 40, 167, 241, 234, 95, 61, 79, 194, 127, 194, 197,
                103>>,
        auth_message =
            <<"n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=409600000,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j">>,
        client_signature =
            <<209, 237, 202, 96, 155, 147, 96, 108, 48, 218, 110, 140, 122, 223, 86, 215, 92, 171,
                193, 19>>,
        client_proof =
            <<207, 29, 243, 62, 184, 171, 13, 138, 177, 64, 39, 210, 244, 105, 100, 75, 18, 43, 106,
                14>>,
        server_key =
            <<222, 94, 85, 104, 169, 47, 131, 128, 114, 6, 162, 90, 225, 108, 19, 88, 133, 210, 62,
                187>>,
        server_signature =
            <<87, 156, 101, 76, 203, 139, 198, 161, 160, 20, 24, 9, 165, 245, 125, 35, 171, 138, 16,
                195>>
    }.
