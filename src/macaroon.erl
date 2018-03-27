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
%%% This module contains operations for manipulating and inspecting macaroons.
%%% @end
%%%-----------------------------------------------------------------------------
-module(macaroon).
-author("Konrad Zemek").

-include("macaroon.hrl").

%% API
-export([create/3, add_first_party_caveat/2, add_third_party_caveat/4,
    prepare_for_request/2]).
-export([is_macaroon/1, third_party_caveats/1, location/1, signature/1,
    identifier/1, inspect/1]).
-export([serialize/1, deserialize/1]).
-export([suggested_secret_length/0]).

%% Behaviour
%% -callback serialize(Macaroon :: macaroon()) ->
%%     {ok, binary()} | {error, Reason :: term()}.
-callback deserialize(Data :: binary()) ->
    #macaroon{} | no_return().

%% Types
-type macaroon() :: #macaroon{}.
-export_type([macaroon/0]).

%%%=============================================================================
%%% API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% Creates a macaroon with set location (hint), key (secret) and id (public)
%% attributes.
%% @end
%%------------------------------------------------------------------------------
-spec create(Location :: iodata(), Key :: iodata(), Id :: iodata()) ->
    macaroon().
create(Location, Key, Id) when not is_binary(Location); not is_binary(Id) ->
    create(iolist_to_binary(Location), Key, iolist_to_binary(Id));
create(Location, Key, Id) ->
    DerivedKey = macaroon_utils:derive_key(Key),
    Signature = crypto:hmac(?HMAC_HASH_ALGORITHM, DerivedKey, Id),
    #macaroon{identifier = Id, location = Location, signature = Signature}.

%%------------------------------------------------------------------------------
%% @doc
%% Returns a new macaroon with new first-party caveat.
%% @end
%%------------------------------------------------------------------------------
-spec add_first_party_caveat(Macaroon :: macaroon(), Caveat :: iodata()) ->
    macaroon().
add_first_party_caveat(#macaroon{} = M, Caveat) when not is_binary(Caveat) ->
    add_first_party_caveat(M, iolist_to_binary(Caveat));
add_first_party_caveat(#macaroon{} = M, Caveat) ->
    Caveats = [Caveat | M#macaroon.caveats],
    NewSig = crypto:hmac(?HMAC_HASH_ALGORITHM, M#macaroon.signature, Caveat),
    M#macaroon{caveats = Caveats, signature = NewSig}.

%%------------------------------------------------------------------------------
%% @doc
%% Returns a new macaroon with new third-party caveat.
%% The caveat is built from given location (hint), key (secret) and id (public)
%% attributes.
%% @end
%%------------------------------------------------------------------------------
-spec add_third_party_caveat(Macaroon :: macaroon(), Location :: iodata(),
    Key :: iodata(), Id :: iodata()) ->
    macaroon().
add_third_party_caveat(#macaroon{} = M, Location, Key, Id)
    when not is_binary(Location); not is_binary(Id) ->
    add_third_party_caveat(M, iolist_to_binary(Location),
        Key, iolist_to_binary(Id));
add_third_party_caveat(#macaroon{} = M, Location, Key, Id) ->
    NonceSize = enacl:secretbox_nonce_size(),
    Nonce = enacl:randombytes(NonceSize),

    OldSig = M#macaroon.signature,
    DerivedKey = macaroon_utils:derive_key(Key),

    CipherText = enacl:secretbox(DerivedKey, Nonce, OldSig),

    Vid = <<Nonce/binary, CipherText/binary>>,
    NewSig = macaroon_utils:macaroon_hash2(Vid, Id, OldSig),

    Caveat = {iolist_to_binary(Id), Vid, iolist_to_binary(Location)},
    M#macaroon{caveats = [Caveat | M#macaroon.caveats], signature = NewSig}.

%%------------------------------------------------------------------------------
%% @doc
%% Returns a list of third-party caveats of the macaroon.
%% Each caveat is represented as a {location (hint), id (public)} tuple.
%% @end
%%------------------------------------------------------------------------------
-spec third_party_caveats(Macaroon :: macaroon()) ->
    [{Location :: binary(), Id :: binary}].
third_party_caveats(#macaroon{caveats = Caveats}) ->
    lists:reverse(lists:filtermap(fun
        ({Id, _Vid, Location}) -> {true, {Location, Id}};
        (_) -> false
    end, Caveats)).

%%------------------------------------------------------------------------------
%% @doc
%% Returns a new discharge macaroon bounded to the parent macaroon.
%% @end
%%------------------------------------------------------------------------------
-spec prepare_for_request(Macaroon :: macaroon(), Dispatch :: macaroon()) ->
    macaroon().
prepare_for_request(#macaroon{} = M, #macaroon{} = D) ->
    NewSig = macaroon_utils:bind_signature(M#macaroon.signature,
        D#macaroon.signature),
    D#macaroon{signature = NewSig}.

%%------------------------------------------------------------------------------
%% @doc
%% Returns if given term is a macaroon.
%% @end
%%------------------------------------------------------------------------------
-spec is_macaroon(term()) -> boolean().
is_macaroon(#macaroon{}) ->
    true;
is_macaroon(_) ->
    false.

%%------------------------------------------------------------------------------
%% @doc
%% Returns macaroon's location (hint) attribute.
%% @end
%%------------------------------------------------------------------------------
-spec location(Macaroon :: macaroon()) -> binary().
location(#macaroon{} = M) ->
    M#macaroon.location.

%%------------------------------------------------------------------------------
%% @doc
%% Returns macaroon's signature.
%% @end
%%------------------------------------------------------------------------------
-spec signature(Macaroon :: macaroon()) -> binary().
signature(#macaroon{} = M) ->
    macaroon_utils:hex_encode(M#macaroon.signature).

%%------------------------------------------------------------------------------
%% @doc
%% Returns macaroon's identifier (public) attribute.
%% @end
%%------------------------------------------------------------------------------
-spec identifier(Macaroon :: macaroon()) -> binary().
identifier(#macaroon{} = M) ->
    M#macaroon.identifier.

%%------------------------------------------------------------------------------
%% @doc
%% Serializes the macaroon into base64url-encoded binary.
%% The serialized format is compatible with libmacaroons reference
%% implementation.
%% @end
%%------------------------------------------------------------------------------
-spec serialize(Macaroon :: macaroon()) ->
    {ok, binary()} | {error, {too_long, term()}}.
serialize(#macaroon{} = M) ->
    try
        Data = macaroon_v1:serialize(M),
        {ok, base64url:encode(iolist_to_binary(Data))}
    catch
        {cannot_serialize, Reason} -> {error, Reason}
    end.

%%------------------------------------------------------------------------------
%% @doc
%% Deserializes a macaroon from base64url-encoded binary.
%% The serialized format must be compatible with libmacaroons reference
%% implementation.
%% @end
%%------------------------------------------------------------------------------
-spec deserialize(Data :: iodata()) ->
    {ok, macaroon()} | {error, macaroon_invalid}.
deserialize(Data) when not is_binary(Data) ->
    deserialize(iolist_to_binary(Data));
deserialize(Data) ->
    try
        DeserializedData = base64url:decode(Data),
        Mod =
            case DeserializedData of
                <<2, _/binary>> -> macaroon_v2;
                _ -> macaroon_v1
            end,
        M = Mod:deserialize(DeserializedData),
        {ok, M}
    catch
        _:_ -> {error, macaroon_invalid}
    end.

%%------------------------------------------------------------------------------
%% @doc
%% Returns a human-readable binary that describes the macaroon.
%% The function is only intended for debugging, and can for example be used
%% with ``io:format("~s", [inspect(M)])''.
%% @end
%%------------------------------------------------------------------------------
-spec inspect(Macaroon :: macaroon()) -> binary().
inspect(#macaroon{} = M) ->
    CaveatsData =
        lists:map(fun
            ({Id, Vid, Location}) ->
                HexVid = macaroon_utils:hex_encode(Vid),
                [
                    ?CID_KEY, <<" ">>, Id, <<"\n">>,
                    ?VID_KEY, <<" ">>, HexVid, <<"\n">>,
                    ?CL_KEY, <<" ">>, Location, <<"\n">>
                ];
            (Caveat) -> [?CID_KEY, <<" ">>, Caveat, <<"\n">>]
        end, lists:reverse(M#macaroon.caveats)),

    HexSignature = macaroon_utils:hex_encode(M#macaroon.signature),

    iolist_to_binary([
        ?LOCATION_KEY, <<" ">>, M#macaroon.location, <<"\n">>,
        ?IDENTIFIER_KEY, <<" ">>, M#macaroon.identifier, <<"\n">>,
        CaveatsData,
        ?SIGNATURE_KEY, <<" ">>, HexSignature, <<"\n">>
    ]).

%%------------------------------------------------------------------------------
%% @doc
%% Returns the ideal length of secret key used for creating macaroons.
%% @end
%%------------------------------------------------------------------------------
-spec suggested_secret_length() -> non_neg_integer().
suggested_secret_length() ->
    ?HMAC_KEYBYTES.
