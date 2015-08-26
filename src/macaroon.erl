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
%%% API for operations on a macaroon.
%%% @end
%%%-------------------------------------------------------------------
-module(macaroon).
-author("Konrad Zemek").

%% API
-export([create/3, add_first_party_caveat/2, add_third_party_caveat/4,
    third_party_caveats/1, prepare_for_request/2, location/1, signature/1,
    identifier/1, serialize/1, deserialize/1, inspect/1, copy/1, compare/2,
    max_strlen/0, max_caveats/0, suggested_secret_length/0]).

%% Internal API
-export([unwrap_/1]).

%% Types
-record(macaroon, {m :: macaroons_nif:macaroon()}).
-type reason() :: macaroons_nif:reason().
-opaque macaroon() :: #macaroon{}.

-export_type([reason/0, macaroon/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec create(Location :: iodata(), Key :: iodata(), Id :: iodata()) ->
    {ok, macaroon()} | {error, reason()}.
create(Location, Key, Id) ->
    wrap(macaroons_nif:create_macaroon(Location, Key, Id)).

-spec add_first_party_caveat(Macaroon :: macaroon(), Caveat :: iodata()) ->
    {ok, macaroon()} | {error, reason()}.
add_first_party_caveat(#macaroon{m = M}, Caveat) ->
    wrap(macaroons_nif:add_first_party_caveat(M, Caveat)).

-spec add_third_party_caveat(Macaroon :: macaroon(), Location :: iodata(),
    Key :: iodata(), Id :: iodata()) ->
    {ok, macaroon()} | {error, reason()}.
add_third_party_caveat(#macaroon{m = M}, Location, Key, Id) ->
    wrap(macaroons_nif:add_third_party_caveat(M, Location, Key, Id)).

-spec third_party_caveats(Macaroon :: macaroon()) ->
    {ok, [{Location :: binary(), Id :: binary}]} | {error, reason()}.
third_party_caveats(#macaroon{m = M}) ->
    macaroons_nif:third_party_caveats(M).

-spec prepare_for_request(Macaroon :: macaroon(), Dispatch :: macaroon()) ->
    {ok, macaroon()} | {error, reason()}.
prepare_for_request(#macaroon{m = M}, #macaroon{m = D}) ->
    wrap(macaroons_nif:prepare_for_request(M, D)).

-spec location(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
location(#macaroon{m = M}) ->
    macaroons_nif:location(M).

-spec signature(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
signature(#macaroon{m = M}) ->
    macaroons_nif:signature(M).

-spec identifier(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
identifier(#macaroon{m = M}) ->
    macaroons_nif:identifier(M).

-spec serialize(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
serialize(#macaroon{m = M}) ->
    macaroons_nif:serialize(M).

-spec deserialize(Data :: iodata()) ->
    {ok, macaroon()} | {error, reason()}.
deserialize(Data) ->
    wrap(macaroons_nif:deserialize(Data)).

-spec inspect(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, reason()}.
inspect(#macaroon{m = M}) ->
    macaroons_nif:inspect(M).

-spec copy(Macaroon :: macaroon()) ->
    {ok, macaroon()} | {error, reason()}.
copy(#macaroon{m = M}) ->
    wrap(macaroons_nif:copy(M)).

-spec compare(A :: macaroon(), B :: macaroon()) -> boolean().
compare(#macaroon{m = A}, #macaroon{m = B}) ->
    macaroons_nif:compare(A, B).

-spec max_strlen() -> non_neg_integer().
max_strlen() ->
    macaroons_nif:max_strlen().

-spec max_caveats() -> non_neg_integer().
max_caveats() ->
    macaroons_nif:max_caveats().

-spec suggested_secret_length() -> non_neg_integer().
suggested_secret_length() ->
    macaroons_nif:suggested_secret_length().

-spec unwrap_(macaroon()) -> macaroons_nif:macaroon().
unwrap_(#macaroon{m = Macaroon}) ->
    Macaroon.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec wrap
    ({ok, macaroons_nif:macaroon()}) -> {ok, macaroon()};
    ({error, reason()}) -> {error, reason()}.
wrap({ok, Macaroon}) -> {ok, #macaroon{m = Macaroon}};
wrap({error, Reason}) -> {error, Reason}.
