%%%-----------------------------------------------------------------------------
%%% @author Konrad Zemek
%%% @copyright (C) 2015, Konrad Zemek <konrad.zemek@gmail.com>
%%% All rights reserved.
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright notice,
%%% this list of conditions and the following disclaimer.
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright notice,
%%% this list of conditions and the following disclaimer in the documentation
%%% and/or other materials provided with the distribution.
%%%
%%% 3. Neither the name of the copyright holder nor the names of its
%%% contributors may be used to endorse or promote products derived from this
%%% software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
%%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
%%% LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
%%% CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
%%% SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
%%% INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
%%% CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
%%% ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%%% POSSIBILITY OF SUCH DAMAGE.
%%% @end
%%%-----------------------------------------------------------------------------
%%% @doc
%%% This module contains operations for verifying macaroons.
%%% @end
%%%-----------------------------------------------------------------------------
-module(macaroon_verifier).
-author("Konrad Zemek").

-include("macaroon.hrl").

%% API
-export([create/0, satisfy_exact/2, satisfy_general/2, verify/3, verify/4]).

%% Types
-type predicate() :: fun((binary()) -> boolean()).
-type auth_error() ::
{unverified_caveat, Caveat :: binary()}
| {bad_signature_for_macaroon, MacaroonId :: binary()}
| {failed_to_decrypt_caveat, CaveatId :: binary()}
| {no_discharge_macaroon_for_caveat, CaveatId :: binary()}.

-record(verifier, {
    exact = sets:new() :: sets:set(binary()),
    general = [] :: [predicate()]
}).

-opaque verifier() :: #verifier{}.
-export_type([predicate/0, verifier/0, auth_error/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%------------------------------------------------------------------------------
%% @doc
%% Creates a new verifier.
%% @end
%%------------------------------------------------------------------------------
-spec create() -> verifier().
create() ->
    #verifier{}.

%%------------------------------------------------------------------------------
%% @doc
%% Returns a new verifier that additionally accepts given exact caveat.
%% @end
%%------------------------------------------------------------------------------
-spec satisfy_exact(Verifier :: verifier(), Predicate :: iodata()) ->
    verifier().
satisfy_exact(#verifier{} = V, Predicate) when not is_binary(Predicate) ->
    satisfy_exact(V, iolist_to_binary(Predicate));
satisfy_exact(#verifier{} = V, Predicate) ->
    V#verifier{exact = sets:add_element(Predicate, V#verifier.exact)}.

%%------------------------------------------------------------------------------
%% @doc
%% Returns a new verifier that uses an additional predicate function to verify
%% caveats.
%% @end
%%------------------------------------------------------------------------------
-spec satisfy_general(Verifier :: verifier(), Predicate :: predicate()) ->
    verifier().
satisfy_general(#verifier{} = V, Predicate) when is_function(Predicate, 1) ->
    V#verifier{general = [Predicate | V#verifier.general]}.

%%------------------------------------------------------------------------------
%% @equiv
%% verify(Verifier, Macaroon, Key, [])
%% @end
%%------------------------------------------------------------------------------
-spec verify(Verifier :: verifier(), Macaroon :: macaroon:macaroon(),
    Key :: iodata()) ->
    ok | {error, auth_error()}.
verify(Verifier, Macaroon, Key) ->
    verify(Verifier, Macaroon, Key, []).

%%------------------------------------------------------------------------------
%% @doc
%% Verifies a macaroon using given discharge macaroons and preconfigured
%% verifier.
%% @end
%%------------------------------------------------------------------------------
-spec verify(Verifier :: verifier(), Macaroon :: macaroon:macaroon(),
    Key :: iodata(), DischargeMacaroons :: [macaroon:macaroon()]) ->
    ok | {error, auth_error()}.
verify(#verifier{} = V, #macaroon{} = M, Key, DischargeMacaroons) ->
    DerivedKey = macaroon_utils:derive_key(Key),
    verify(M#macaroon.signature, V, M, DerivedKey, DischargeMacaroons).


%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec verify(ParentSig :: binary(), Verifier :: verifier(),
    Macaroon :: macaroon:macaroon(), Key :: binary(),
    DischargeMacaroons :: [macaroon:macaroon()]) ->
    ok | {error, auth_error()}.
verify(ParentSig, V, M, Key, DischargeMacaroons) ->
    BaseSignature =
        crypto:hmac(?HMAC_HASH_ALGORITHM, Key, M#macaroon.identifier),

    VerifyResult =
        verify_loop(ParentSig, V, DischargeMacaroons,
            lists:reverse(M#macaroon.caveats), BaseSignature),

    case VerifyResult of
        {ok, Signature} ->
            BoundSignature =
                macaroon_utils:bind_signature(ParentSig, Signature),

            case BoundSignature =:= M#macaroon.signature of
                true -> ok;
                false ->
                    {error, {bad_signature_for_macaroon, M#macaroon.identifier}}
            end;

        {error, Reason} -> {error, Reason}
    end.


-spec verify_loop(ParentSig :: binary(), Verifier :: verifier(),
    DMs :: [macaroon:macaroon()],
    Caveats :: [binary() | {binary(), binary(), binary()}],
    Signature :: binary()) ->
    {ok, FinalSig :: binary()} | {error, auth_error()}.
verify_loop(_ParentSig, _V, _DMs, [], Signature) -> {ok, Signature};

verify_loop(ParentSig, V, DMs, [{Id, Vid, _Location} | Caveats], Signature) ->
    NonceSize = enacl:secretbox_nonce_size(),
    <<Nonce:NonceSize/binary, CipherText/binary>> = Vid,

    OpenBoxResult =
        enacl:secretbox_open(CipherText, Nonce, Signature),

    case OpenBoxResult of
        {error, _} -> {error, {failed_to_decrypt_caveat, Id}};
        {ok, Key} ->
            {DMsBefore, DMsAfterWithPivot} =
                lists:splitwith(fun(M) ->
                    M#macaroon.identifier =/= Id end, DMs),

            case DMsAfterWithPivot of
                [] -> {error, {no_discharge_macaroon_for_caveat, Id}};
                [DM | DMsAfter] ->
                    OtherDMs = DMsBefore ++ DMsAfter,
                    case verify(ParentSig, V, DM, Key, OtherDMs) of
                        {error, Reason} -> {error, Reason};
                        ok ->
                            NewSig = macaroon_utils:macaroon_hash2(Vid, Id,
                                Signature),
                            verify_loop(ParentSig, V, OtherDMs, Caveats, NewSig)
                    end
            end
    end;

verify_loop(ParentSig, V, DMs, [Caveat | Caveats], Signature) ->
    case caveat_verifies(V, Caveat) of
        false -> {error, {unverified_caveat, Caveat}};
        true ->
            NewSig = crypto:hmac(?HMAC_HASH_ALGORITHM, Signature, Caveat),
            verify_loop(ParentSig, V, DMs, Caveats, NewSig)
    end.


-spec caveat_verifies(Verifier :: verifier(), Caveat :: binary()) -> boolean().
caveat_verifies(V, Caveat) ->
    case sets:is_element(Caveat, V#verifier.exact) of
        true -> true;
        false ->
            lists:any(fun(General) -> General(Caveat) end, V#verifier.general)
    end.
