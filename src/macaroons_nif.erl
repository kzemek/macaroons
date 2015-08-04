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
%%% Erlang-side definition of libmacaroons NIF-wrapped functions.
%%% @end
%%%-------------------------------------------------------------------
-module(macaroons_nif).
-author("Konrad Zemek").

-on_load(init/0).

%% API
-export([create_macaroon/3, add_first_party_caveat/2, add_third_party_caveat/4,
    third_party_caveats/1, prepare_for_request/2, create_verifier/0,
    satisfy_exact/2, satisfy_general/2, start_verify_thread/5,
    join_verify_thread/1, set_verify_status/2, location/1, signature/1,
    identifier/1, serialize/1, deserialize/1, inspect/1, copy/1, compare/2,
    max_strlen/0, max_caveats/0, suggested_secret_length/0]).

%% Types
-type reason() :: buffer_too_small | discharge_caveats_form_a_cycle |
hmac_function_failed |not_authorized | json_macaroons_not_supported |
too_many_caveats |macaroon_invalid |unknown_error| any().

-type macaroon() :: term().
-type verifier() :: term().
-type thread() :: term().
-type promise() :: term().

-export_type([reason/0, macaroon/0, verifier/0, thread/0, promise/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec create_macaroon(Location :: iolist(), Key :: iolist(), Id :: iolist()) ->
    {ok, macaroon()} | {error, reason()}.
create_macaroon(_Location, _Key, _Id) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec add_first_party_caveat(Macaroon :: macaroon(), Caveat :: iolist()) ->
    {ok, macaroon()} | {error, reason()}.
add_first_party_caveat(_Macaroon, _Caveat) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec add_third_party_caveat(Macaroon :: macaroon(), Location :: iolist(),
    Key :: iolist(), Id :: iolist()) ->
    {ok, macaroon()} | {error, reason()}.
add_third_party_caveat(_Macaroon, _Location, _Key, _Id) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec third_party_caveats(Macaroon :: macaroon()) ->
    {ok, [{Location :: binary(), Id :: binary}]} | {error, reason()}.
third_party_caveats(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec prepare_for_request(Macaroon :: macaroon(), Dispatch :: macaroon()) ->
    {ok, macaroon()} | {error, reason()}.
prepare_for_request(_Macaroon, _Dispatch) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec create_verifier() ->
    {ok, verifier()} | {error, reason()}.
create_verifier() ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec satisfy_exact(Verifier :: verifier(), Predicate :: iolist()) ->
    ok | {error, reason()}.
satisfy_exact(_Verifier, _Predicate) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec satisfy_general(Verifier :: verifier(),
    Predicate :: fun((binary()) -> boolean())) ->
    ok | {error, reason()}.
satisfy_general(_Verifier, _Predicate) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec start_verify_thread(Verifier :: verifier(), Macaroon :: macaroon(),
    Key :: iolist(), DischargeMacaroons :: [macaroon()], Ref :: reference()) ->
    thread().
start_verify_thread(_Verifier, _Macaroon, _Key, _DischargeMacaroons, _Ref) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec join_verify_thread(Thread :: thread()) -> ok.
join_verify_thread(_Thread) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec set_verify_status(Promise :: promise(), Status :: boolean()) -> ok.
set_verify_status(_Promise, _Status) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec location(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
location(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec signature(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
signature(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec identifier(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
identifier(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec serialize(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
serialize(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec deserialize(Data :: iolist()) ->
    {ok, macaroon()} | {error, reason()}.
deserialize(_Data) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec inspect(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
inspect(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec copy(Macaroon :: macaroon()) ->
    {ok, macaroon()} | {error, reason()}.
copy(_Macaroon) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec compare(A :: macaroon(), B :: macaroon()) -> boolean().
compare(_A, _B) ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec max_strlen() -> non_neg_integer().
max_strlen() ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec max_caveats() -> non_neg_integer().
max_caveats() ->
    erlang:nif_error(macaroons_nif_not_loaded).

-spec suggested_secret_length() -> non_neg_integer().
suggested_secret_length() ->
    erlang:nif_error(macaroons_nif_not_loaded).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initialization function for the module.
%% Loads the NIF native library. The library is first searched for
%% in application priv dir, and then under ../priv and ./priv .
%% @end
%%--------------------------------------------------------------------
-spec init() -> ok | {error, Reason :: atom()}.
init() ->
    LibName = "libmacaroons_nif",
    LibPath =
        case code:priv_dir(ssl2) of
            {error, bad_name} ->
                case filelib:is_dir(filename:join(["..", priv])) of
                    true ->
                        filename:join(["..", priv, LibName]);
                    _ ->
                        filename:join([priv, LibName])
                end;

            Dir ->
                filename:join(Dir, LibName)
        end,

    erlang:load_nif(LibPath, 0).
