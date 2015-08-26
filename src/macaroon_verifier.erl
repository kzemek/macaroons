%%%-------------------------------------------------------------------
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
%%%--------------------------------------------------------------------
%%% @doc
%%% API for operations on a verifier.
%%% @end
%%%-------------------------------------------------------------------
-module(macaroon_verifier).
-author("Konrad Zemek").

%% API
-export([create/0, satisfy_exact/2, satisfy_general/2, verify/3, verify/4]).

%% Types
-record(verifier, {v :: macaroons_nif:verifier()}).
-type reason() :: macaroons_nif:reason().
-opaque verifier() :: #verifier{}.

-export_type([reason/0, verifier/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec create() ->
    {ok, verifier()} | {error, reason()}.
create() ->
    case macaroons_nif:create_verifier() of
        {ok, V} -> {ok, #verifier{v = V}};
        Other -> Other
    end.

-spec satisfy_exact(Verifier :: verifier(), Predicate :: iodata()) ->
    ok | {error, reason()}.
satisfy_exact(#verifier{v = V}, Predicate) ->
    macaroons_nif:satisfy_exact(V, Predicate).

-spec satisfy_general(Verifier :: verifier(),
    Predicate :: fun((binary()) -> boolean())) ->
    ok | {error, reason()}.
satisfy_general(#verifier{v = V}, Predicate) ->
    macaroons_nif:satisfy_general(V, Predicate).

-spec verify(Verifier :: verifier(), Macaroon :: macaroon:macaroon(),
    Key :: iodata()) ->
    ok | {error, not_authorized | reason()}.
verify(Verifier, Macaroon, Key) ->
    verify(Verifier, Macaroon, Key, []).

-spec verify(Verifier :: verifier(), Macaroon :: macaroon:macaroon(),
    Key :: iodata(), DischargeMacaroons :: [macaroon:macaroon()]) ->
    ok | {error, not_authorized | reason()}.
verify(#verifier{v = V}, WrappedMacaroon, Key, DischargeMacaroons) ->
    MS = [macaroon:unwrap_(Macaroon) || Macaroon <- DischargeMacaroons],
    Ref = make_ref(),

    Thread = macaroons_nif:start_verify_thread(V,
        macaroon:unwrap_(WrappedMacaroon), Key, MS, Ref),

    VerifyResult = verify_loop(Ref),
    ok = macaroons_nif:join_verify_thread(Thread),
    VerifyResult.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec verify_loop(Ref :: reference()) ->
    ok | {error, reason()}.
verify_loop(Ref) ->
    receive
        {Ref, Fun, Promise, Predicate} ->
            Result = Fun(Predicate),
            ok = macaroons_nif:set_verify_status(Promise, Result),
            verify_loop(Ref);
        {Ref, done, VerifyResult} ->
            VerifyResult
    end.
