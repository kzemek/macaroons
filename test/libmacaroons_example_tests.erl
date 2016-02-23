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
%%% Tests for Macaroons checking if libmacaroons examples are correctly handled.
%%% @end
%%%-------------------------------------------------------------------
-module(libmacaroons_example_tests).
-author("Konrad Zemek").

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test cases
%%%===================================================================

libmacaroons_first_party_example_test() ->
    Secret = <<"this is our super secret key; only we should know it">>,
    Public = <<"we used our secret key">>,
    Location = <<"http://mybank/">>,

    M = macaroon:create(Location, Secret, Public),

    ?assertEqual(Public, macaroon:identifier(M)),
    ?assertEqual(Location, macaroon:location(M)),
    ?assertEqual(
        <<"e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f">>,
        macaroon:signature(M)),
    ?assertEqual(
        {ok, <<"MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo">>},
        macaroon:serialize(M)),

    M1 = macaroon:add_first_party_caveat(M, <<"account = 3735928559">>),
    ?assertEqual(
        <<"1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128">>,
        macaroon:signature(M1)),

    M2 = macaroon:add_first_party_caveat(M1, <<"time < 2020-01-01T00:00">>),
    ?assertEqual(
        <<"b5f06c8c8ef92f6c82c6ff282cd1f8bd1849301d09a2db634ba182536a611c49">>,
        macaroon:signature(M2)),

    M3 = macaroon:add_first_party_caveat(M2, <<"email = alice@example.org">>),
    ?assertEqual(
        <<"ddf553e46083e55b8d71ab822be3d8fcf21d6bf19c40d617bb9fb438934474b6">>,
        macaroon:signature(M3)),

    {ok, Msg} = macaroon:serialize(M3),
    ?assertEqual({ok, M3}, macaroon:deserialize(Msg)),

    V = macaroon_verifier:create(),
    ?assertEqual(
        {error, {unverified_caveat, <<"account = 3735928559">>}},
        macaroon_verifier:verify(V, M3, Secret)),

    V1 = macaroon_verifier:satisfy_exact(V, <<"account = 3735928559">>),
    V2 = macaroon_verifier:satisfy_exact(V1, <<"email = alice@example.org">>),
    V3 = macaroon_verifier:satisfy_exact(V2, <<"IP = 127.0.0.1">>),
    V4 = macaroon_verifier:satisfy_exact(V3, <<"browser = Chrome">>),
    V5 = macaroon_verifier:satisfy_exact(V4, <<"action = deposit">>),

    CheckTime = fun
        (<<"time < ", DateTime/binary>>) -> DateTime =:= <<"2020-01-01T00:00">>;
        (_) -> false
    end,

    V6 = macaroon_verifier:satisfy_general(V5, CheckTime),
    ?assertEqual(ok, macaroon_verifier:verify(V6, M3, Secret)),

    N = macaroon:add_first_party_caveat(M3, <<"action = deposit">>),
    ?assertEqual(ok, macaroon_verifier:verify(V6, N, Secret)),

    N2 = macaroon:add_first_party_caveat(M, <<"OS = Windows XP">>),
    ?assertEqual(
        {error, {unverified_caveat, <<"OS = Windows XP">>}},
        macaroon_verifier:verify(V6, N2, Secret)),

    N3 = macaroon:add_first_party_caveat(M, <<"time < 2014-01-01T00:00">>),
    ?assertEqual(
        {error, {unverified_caveat, <<"time < 2014-01-01T00:00">>}},
        macaroon_verifier:verify(V6, N3, Secret)),

    ?assertEqual(
        {error, {bad_signature_for_macaroon, Public}},
        macaroon_verifier:verify(V6, M,
            <<"this is not the secret we were looking for">>)),

    {ok, N4} = macaroon:deserialize(
        <<"MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNl\nY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDIwY2lkIHRpbWUgPCAyMDIw\nLTAxLTAxVDAwOjAwCjAwMjJjaWQgZW1haWwgPSBhbGljZUBleGFtcGxlLm9yZwowMDJmc2lnbmF0\ndXJlID8f19FL+bkC9p/aoMmIecC7GxdOcLVyUnrv6lJMM7NSCg==\n">>),
    ?assertNotEqual(macaroon:signature(M3), macaroon:signature(N4)),
    ?assertEqual(
        {error, {bad_signature_for_macaroon, Public}},
        macaroon_verifier:verify(V6, N4, Secret)).


libmacaroons_third_party_example_test() ->
    Secret =
        <<"this is a different super-secret key; never use the same secret twice">>,
    Public = <<"we used our other secret key">>,
    Location = <<"http://mybank/">>,
    M = macaroon:create(Location, Secret, Public),
    M1 = macaroon:add_first_party_caveat(M, <<"account = 3735928559">>),

    CaveatKey = <<"4; guaranteed random by a fair toss of the dice">>,
    Identifier = <<"this was how we remind auth of key/pred">>,
    M2 = macaroon:add_third_party_caveat(M1, <<"http://auth.mybank/">>,
        CaveatKey, Identifier),

    ?assertEqual(
        [{<<"http://auth.mybank/">>, <<"this was how we remind auth of key/pred">>}],
        macaroon:third_party_caveats(M2)),

    D = macaroon:create("http://auth.mybank/", CaveatKey, Identifier),
    D2 = macaroon:add_first_party_caveat(D, "time < 2020-01-01T00:00"),
    DP = macaroon:prepare_for_request(M2, D2),

    ?assertNotEqual(macaroon:signature(D2), macaroon:signature(DP)),

    V = macaroon_verifier:create(),
    V1 = macaroon_verifier:satisfy_exact(V, <<"account = 3735928559">>),

    CheckTime = fun
        (<<"time < ", DateTime/binary>>) -> DateTime =:= <<"2020-01-01T00:00">>;
        (_) -> false
    end,

    V2 = macaroon_verifier:satisfy_general(V1, CheckTime),

    ?assertEqual(ok, macaroon_verifier:verify(V2, M2, Secret, [DP])),
    ?assertEqual(
        {error, {bad_signature_for_macaroon, Identifier}},
        macaroon_verifier:verify(V2, M2, Secret, [D2])).
