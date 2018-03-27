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
%%% This module contains operations encoding and decoding v2 binary macaroon format.
%%% @end
%%%-----------------------------------------------------------------------------
-module(macaroon_v2).
-author("Konrad Zemek").

-include("macaroon.hrl").
-behaviour(macaroon).

-define(LOCATION, 1).
-define(IDENTIFIER, 2).
-define(VID, 4).
-define(SIGNATURE, 6).

%% API
-export([deserialize/1]).

%%%=============================================================================
%%% API
%%%=============================================================================

deserialize(Bin) ->
    <<2, Bin1/binary>> = Bin,
    {Loc, Bin2} = try_read_field(?LOCATION, Bin1),
    {Ident, Bin3} = read_field(?IDENTIFIER, Bin2),
    <<0, Bin4/binary>> = Bin3,
    {Caveats, Bin5} = read_caveats(Bin4, []),
    {Sig, <<>>} = read_field(?SIGNATURE, Bin5),
    #macaroon{identifier = Ident, location = Loc,
              caveats = Caveats, signature = Sig}.

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

read_caveats(<<0, Rest/binary>>, Acc) ->
    {lists:reverse(Acc), Rest};
read_caveats(Bin, Acc) ->
    {Caveat, Bin1} = read_caveat(Bin),
    read_caveats(Bin1, [Caveat | Acc]).

read_caveat(Bin) ->
    {Loc, Bin1} = try_read_field(?LOCATION, Bin),
    {Ident, Bin2} = read_field(?IDENTIFIER, Bin1),
    {Vid, Bin3} = try_read_field(?VID, Bin2),
    <<0, Bin4/binary>> = Bin3,
    Caveat =
        case {Loc, Vid} of
            {undefined, undefined} -> Ident;
            {<<_/binary>>, <<_/binary>>} -> {Ident, Vid, Loc}
        end,
    {Caveat, Bin4}.

try_read_field(ExpectedType, Bin0) ->
    case read_varint(Bin0) of
        {ExpectedType, Bin1} ->
            {FieldLength, Bin2} = read_varint(Bin1),
            <<FieldContent:FieldLength/binary, Bin3/binary>> = Bin2,
            {FieldContent, Bin3};
        _ ->
            {undefined, Bin0}
    end.

read_field(ExpectedType, Bin) ->
    {<<_/binary>>, _} = try_read_field(ExpectedType, Bin).

read_varint(Bin) when is_binary(Bin) ->
    read_varint(Bin, <<>>, 0).

read_varint(<<1:1, X:7, Rest/binary>>, Acc, Size) ->
    read_varint(Rest, <<X:7, Acc/binary>>, Size + 1);
read_varint(<<0:1, X:7, Rest/binary>>, Acc, Size0) ->
    Size = Size0 + 1,
    BytesNeeded = (Size * 7 + 7) div 8,
    Padding = BytesNeeded * 8 - Size * 7,
    Bin = <<0:Padding, X:7, Acc/bitstring>>,
    Int = binary:decode_unsigned(Bin, big),
    {Int, Rest}.
