-module(fast_scram_attributes).

-include("types.hrl").

-export([
         reserved_scram_codes/0,
         gs2_header/2,
         nonce/1,
         cbind_input/2,
         client_first_message_bare/2,
         client_final_message_without_proof/3,
         server_first_message/2,
         client_first_message/3,
         client_final_message/2,
         server_final_message/1
        ]).

%%%===================================================================
%%% SCRAM attributes
%%%===================================================================

% -type scram_attribute() ::
%     'a=' | % auth as a different user
%     'n=' | % username, auth identity
%     'm=' | % reserved for extensibility
%     'r=' | % nonce
%     'c=' | % GS2 header and channel binding data
%     's=' | % base64 salt
%     'i=' | % iteration count
%     'p=' | % base64 ClientProof
%     'v=' | % base64 ServerSignature
%     'e='.  % error that occurred during auth
reserved_scram_codes() ->
    [<<"p">>, <<"n">>, <<"r">>,
     <<"c">>, <<"s">>, <<"i">>,
     <<"a">>, <<"v">>, <<"e">>].


% gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"
%                   ;; "n" -> client doesn't support channel binding.
%                   ;; "y" -> client does support channel binding
%                   ;;        but thinks the server does not.
%                   ;; "p" -> client requires channel binding.
%                   ;; The selected channel binding follows "p=".
gs2_cbind_flag(undefined) ->
    <<"n">>;
gs2_cbind_flag(none) ->
    <<"y">>;
gs2_cbind_flag(CB) when is_binary(CB) ->
    <<"p=", CB/binary>>.

% authzid         = "a=" saslname
%                   ;; Protocol specific.
authzid(ID) when is_binary(ID) ->
    ID.

% gs2-header      = gs2-cbind-flag "," [ authzid ] ","
%                   ;; GS2 header for SCRAM
%                   ;; (the actual GS2 header includes an optional
%                   ;; flag to indicate that the GSS mechanism is not
%                   ;; "standard", but since SCRAM is "standard", we
%                   ;; don't include that flag).
gs2_header(#channel_binding{variant = Variant}, Data) ->
    AuthZID = maps:get(auth_zid, Data, <<>>),
    <<(gs2_cbind_flag(Variant))/binary, ",",
      (authzid(AuthZID))/binary, ",">>.

% reserved-mext  = "m=" 1*(value-char)
%                   ;; Reserved for signaling mandatory extensions.
%                   ;; The exact syntax will be defined in
%                   ;; the future.
reserved_mext() ->
    <<"">>.

% username        = "n=" saslname
%                   ;; Usernames are prepared using SASLprep.
username(Username) ->
    <<"n=", Username/binary>>.

% nonce           = "r=" c-nonce [s-nonce]
%                   ;; Second part provided by server.
nonce(#nonce{client = CNonce, server = SNonce}) ->
    <<"r=", CNonce/binary, SNonce/binary>>.

% extensions = attr-val *("," attr-val)
%                   ;; All extensions are optional,
%                   ;; i.e., unrecognized attributes
%                   ;; not defined in this document
%                   ;; MUST be ignored.
extensions() ->
    <<>>.

%salt            = "s=" base64
salt(Salt) ->
    <<"s=", (base64:encode(Salt))/binary>>.

% iteration-count = "i=" posit-number
%                   ;; A positive number.
iteration_count(IterationCount) when ?is_positive_integer(IterationCount) ->
    <<"i=", (integer_to_binary(IterationCount))/binary>>.

% channel-binding = "c=" base64
%                      ;; base64 encoding of cbind-input.
channel_binding(#channel_binding{data = CBindData} = CBindConfig, Data) ->
    <<"c=", (cbind_input(gs2_header(CBindConfig, Data), CBindData))/binary>>.

cbind_input(GS2Header, CBindData) ->
    base64:encode(<<GS2Header/binary, CBindData/binary>>).

% proof           = "p=" base64
proof(Proof)->
    <<"p=", (base64:encode(Proof))/binary>>.

%%%===================================================================
%%% SCRAM Messages
%%%===================================================================
% client-first-message-bare =
%                   [reserved-mext ","]
%                   username "," nonce ["," extensions]
client_first_message_bare(#{username := Username}, Nonce)->
    <<(reserved_mext())/binary,
      (username(Username))/binary, ",",
      (nonce(Nonce))/binary,
      (extensions())/binary>>.

% client-final-message-without-proof =
%                   channel-binding "," nonce ["," extensions]
client_final_message_without_proof(CBConfig, Nonce, Data) ->
    <<(channel_binding(CBConfig, Data))/binary, ",",
      (nonce(Nonce))/binary,
      (extensions())/binary>>.

% client-first-message =
%                   gs2-header client-first-message-bare
client_first_message(CbConfig, Nonce, Data) ->
    GS2Header = gs2_header(CbConfig, Data),
    ClientFirstMessageBare = client_first_message_bare(Data, Nonce),
    {GS2Header, ClientFirstMessageBare}.

% server-first-message =
%                   [reserved-mext ","] nonce "," salt ","
%                   iteration-count ["," extensions]
server_first_message(Nonce, #challenge{salt = Salt, it_count = IterationCount}) ->
    <<(reserved_mext())/binary,
      (nonce(Nonce))/binary, ",",
      (salt(Salt))/binary, ",",
      (iteration_count(IterationCount))/binary,
      (extensions())/binary>>.

% client-final-message =
%                   client-final-message-without-proof "," proof
client_final_message(ClientFinalNoProof, ClientProof) ->
    <<ClientFinalNoProof/binary, ",",
      (proof(ClientProof))/binary>>.

% server-error = "e=" server-error-value

% server-error-value = "invalid-encoding" /
%                "extensions-not-supported" /  ; unrecognized 'm' value
%                "invalid-proof" /
%                "channel-bindings-dont-match" /
%                "server-does-support-channel-binding" /
%                  ; server does not support channel binding
%                "channel-binding-not-supported" /
%                "unsupported-channel-binding-type" /
%                "unknown-user" /
%                "invalid-username-encoding" /
%                  ; invalid username encoding (invalid UTF-8 or
%                  ; SASLprep failed)
%                "no-resources" /
%                "other-error" /
%                server-error-value-ext
%         ; Unrecognized errors should be treated as "other-error".
%         ; In order to prevent information disclosure, the server
%         ; may substitute the real reason with "other-error".

% server-error-value-ext = value
%         ; Additional error reasons added by extensions
%         ; to this document.

% verifier        = "v=" base64
%                   ;; base-64 encoded ServerSignature.

% server-final-message = (server-error / verifier)
%                   ["," extensions]
server_final_message({error, Reason}) ->
    <<"e=", Reason/binary, (extensions())/binary>>;
server_final_message(Verifier) when is_binary(Verifier) ->
    <<"v=", Verifier/binary, (extensions())/binary>>.
