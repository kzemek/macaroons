%%%-----------------------------------------------------------------------------
%%% @author Konrad Zemek
%%% @copyright (C) 2018, Konrad Zemek <konrad.zemek@gmail.com>
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
%%% This module contains operations encoding and decoding v1 binary macaroon format.
%%% @end
%%%-----------------------------------------------------------------------------
-module(macaroon_v1).
-author("Konrad Zemek").

-include("macaroon.hrl").
-behaviour(macaroon).

%% API
-export([serialize/1, deserialize/1]).

%%%=============================================================================
%%% API
%%%=============================================================================

serialize(#macaroon{} = M) ->
    CaveatsData =
        lists:reverse(
          lists:map(
            fun
                ({Id, Vid, Location}) ->
                    [
                     pack(?CID_KEY, Id),
                     pack(?VID_KEY, Vid),
                     pack(?CL_KEY, Location)
                    ];
                (Caveat) ->
                    pack(?CID_KEY, Caveat)
            end, M#macaroon.caveats)),
    [
     pack(?LOCATION_KEY, M#macaroon.location),
     pack(?IDENTIFIER_KEY, M#macaroon.identifier),
     CaveatsData,
     pack(?SIGNATURE_KEY, M#macaroon.signature)
    ].

-spec deserialize(Data :: binary()) ->
                         #macaroon{} | no_return().
deserialize(Data) ->
    deserialize(Data, #macaroon{}, undefined).

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

-spec pack(Key :: binary(), Value :: binary()) -> iolist().
pack(Key, Value) ->
    DataSize = ?PACKET_HEADER_SIZE + 2 + byte_size(Key) + byte_size(Value),
    SizeEncoded =
        list_to_binary(string:to_lower(integer_to_list(DataSize, 16))),

    PaddingSize = ?PACKET_HEADER_SIZE - byte_size(SizeEncoded),
    case PaddingSize < 0 of
        true -> throw({cannot_serialize, {too_long, {Key, Value}}});
        false ->
            [
             binary:copy(<<"0">>, PaddingSize), SizeEncoded,
             Key, <<" ">>, Value, <<"\n">>
            ]
    end.

-spec deserialize(Data :: binary(), #macaroon{},
                  LastCidVid :: undefined | {binary(), binary()}) ->
                         #macaroon{} | no_return().
deserialize(<<>>, #macaroon{} = M, undefined) -> M;
deserialize(Data, #macaroon{} = M, LastCidVid) ->
    <<BinLineSize:?PACKET_HEADER_SIZE/binary, DataWithoutHeader/binary>> = Data,
    LineSize = binary_to_integer(BinLineSize, 16),
    ContentSize = LineSize - ?PACKET_HEADER_SIZE - 1,

    <<Content:ContentSize/binary, "\n", RestLines/binary>> = DataWithoutHeader,
    [Key, Value] = binary:split(Content, <<" ">>),

    {NewM, NewLastCidVid} =
        case {Key, M, LastCidVid} of
            {?LOCATION_KEY, #macaroon{location = undefined}, _} ->
                {M#macaroon{location = Value}, LastCidVid};

            {?IDENTIFIER_KEY, #macaroon{identifier = undefined}, _} ->
                {M#macaroon{identifier = Value}, LastCidVid};

            {?SIGNATURE_KEY, #macaroon{signature = undefined}, _} ->
                {M#macaroon{signature = Value}, LastCidVid};

            {?CID_KEY, #macaroon{caveats = Rest}, undefined} ->
                {M#macaroon{caveats = [Value | Rest]}, undefined};

            {?VID_KEY, #macaroon{caveats = [Cid | Rest]}, undefined} ->
                {M#macaroon{caveats = Rest}, {Cid, Value}};

            {?CL_KEY, #macaroon{caveats = Rest}, {Cid, Vid}} ->
                {M#macaroon{caveats = [{Cid, Vid, Value} | Rest]}, undefined}
        end,

    deserialize(RestLines, NewM, NewLastCidVid).
