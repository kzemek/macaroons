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
%%% Common functions for macaroon and macaroon_verifier modules.
%%% @end
%%%-----------------------------------------------------------------------------
-module(macaroon_utils).
-author("Konrad Zemek").

-include("macaroon.hrl").

%% API
-export([derive_key/1, bind_signature/2, macaroon_hash2/3, hex_encode/1]).

%%%=============================================================================
%%% API
%%%=============================================================================

-spec derive_key(VariableKey :: iodata()) -> binary().
derive_key(VariableKey) ->
    KeySize = enacl_p:auth_key_size(?HMAC_HASH_ALGORITHM),
    ZeroesNum = KeySize - byte_size(?LIBMACAROONS_MAGIC_KEY),
    Key = <<?LIBMACAROONS_MAGIC_KEY/binary,
        0:ZeroesNum/little-signed-integer-unit:8>>,
    enacl_p:auth(?HMAC_HASH_ALGORITHM, VariableKey, Key).


-spec bind_signature(ParentSig :: binary(), DischargeSig :: binary()) ->
    binary().
bind_signature(ParentSig, ParentSig) -> ParentSig;
bind_signature(ParentSig, DischargeSig) ->
    KeySize = enacl_p:auth_key_size(?HMAC_HASH_ALGORITHM),
    Key = <<0:KeySize/little-signed-integer-unit:8>>,
    macaroon_utils:macaroon_hash2(ParentSig, DischargeSig, Key).


-spec macaroon_hash2(Data1 :: iodata(), Data2 :: iodata(), Key :: iodata()) ->
    binary().
macaroon_hash2(Data1, Data2, Key) ->
    Hash1 = enacl_p:auth(?HMAC_HASH_ALGORITHM, Data1, Key),
    Hash2 = enacl_p:auth(?HMAC_HASH_ALGORITHM, Data2, Key),
    enacl_p:auth(?HMAC_HASH_ALGORITHM, [Hash1, Hash2], Key).


-spec hex_encode(Data :: binary()) -> binary().
hex_encode(Data) ->
    <<<<(string:to_lower(Y))>> ||
        <<X:4>> <= Data, Y <- integer_to_list(X, 16)>>.
