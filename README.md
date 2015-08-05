> Note: This README file is a slightly adapted version of README from
> [rescrv/libmacaroons][1].

Macaroons are Better Than Cookies!
==================================

This library is an Erlang wrapper for [libmacaroons][2], a library which
provides an implementation of [macaroons][3].  Macaroons are flexible
authorization tokens that work great in distributed systems.  Like cookies,
macaroons are bearer tokens that enable applications to ascertain whether their
holders' actions are authorized.  But macaroons are better than cookies!

Why Macaroons?
--------------

Macaroons are great for authorization because they're similar enough to cookies
to be immediately usable by developers, but they include several features not
present in cookies or other token-based authorization schemes.  In particular:

 - Delegation with Contextual Caveats (i.e., confinement of the usage context):  
   Macaroons support delegation.  Give your macaroon to another user, and they 
   can act on your behalf, with the same authority.  Cookies permit delegation 
   as well, but the remaining features of macaroons make it much more safe and
   practical to pass around macaroons than cookies.  In particular, macaroons
   can limit when, where, and by whom the delegated authority can be exercised
   (e.g., within one minute, from a machine that holds a certain key, or by a 
   certain logged-in user), by using attenuation and third-party caveats.

 - Attenuation:  Macaroons enable users to add caveats to the macaroon that
   attenuate how, when, and where it may be used.  Unlike cookies, macaroons
   permit their holder to attenuate them before delegating.  Whereas cookies and
   authorization tokens enable an application to get access to all of your data
   and to perform actions on your behalf with your full privileges, macaroons
   enable you to restrict what they can do. Those questionable startups that
   "just want the address book, we swear it," become a whole lot more secure
   when the target application supports macaroons, because macaroons enable you
   to add caveats that restrict what the application can do.

 - Proof-Carrying:  Macaroons are efficient, because they carry their own proof
   of authorization---cryptographically secured, of course.  A macaroon's
   caveats are constructed using chained HMAC functions, which makes it really
   easy to add a caveat, but impossible to remove a caveat.  When you attenuate
   a macaroon and give it to another application, there is no way to strip the
   caveats from the macaroon.  It's easy for the entity that created a macaroon
   to verify the embedded proof, but others cannot.

 - Third-Party Caveats:  Macaroons allow caveats to specify predicates that are
   enforced by third parties.  A macaroon with a third-party caveat will only be
   authorized when the third party certifies that the caveat is satisfied.  This
   enables loosely coupled distributed systems to work together to authorize
   requests.  For example, a data store can provide macaroons that are
   authorized if and only if the application's authentication service says that
   the user is authenticated.  The user obtains a proof that it is
   authenticated from the authentication service, and presents this proof
   alongside the original macaroon to the storage service.  The storage service
   can verify that the user is indeed authenticated, without knowing anything
   about the authentication service's implementation---in a standard
   implementation, the storage service can authorize the request without even
   communicating with the authentication service.

 - Simple Verification:  Macaroons eliminate complexity in the authorization
   code of your application.  Instead of hand-coding complex conditionals in
   each routine that deals with authorization, and hoping that this logic is
   globally consistent, you construct a general verifier for macaroons.  This
   verifier knows how to soundly check the proofs embedded within macaroons to
   see if they do indeed authorize access.

 - Decoupled Authorization Logic:  Macaroons separate the policy of your
   application (who can access what, when), from the mechanism (the code that
   actually upholds this policy).  Because of the way the verifier is
   constructed, it is agnostic to the actual underlying policies it is
   enforcing.  It simply observes the policy (in the form of an embedded proof)
   and certifies that the proof is correct.  The policy itself is specified when
   macaroons are created, attenuated, and shared.  You can easily audit this
   code within your application, and ensure that it is upheld everywhere.

The rest of this document walks through the specifics of macaroons and see just
how easy authorization can be.  So pour a fresh cup of espresso to enjoy
alongside your macaroons and read on!

Installing Macaroons
--------------------

libmacaroons-erlang includes source code of libmacaroons (located in
`c_src/libmacaroons` directory).  As with libmacaroons, you'll need to somehow
install [libsodium][5].  It's packaged in some Linux distributions, and can be
installed from source on most *NIX platforms.  The library is NIF-based, so
it also requires a C++14-compliant compiler.

The installation of libmacaroons-erlang is trivial, provided your Erlang
application uses [rebar][6] for dependency management. Simply add the library
to the list of dependencies in rebar.conf:

```Erlang
{deps, [
    {macaroons, "0.5.1", {git, "https://github.com/kzemek/libmacaroons-erlang.git", {tag, "0.5.1"}}}
]}.
```

Creating Your First Macaroon
----------------------------

Imagine that you ran a bank, and were looking to use macaroons as the basis of
your authorization logic.  Assuming you already installed libmacaroons, you can
create a macaroon like this:

```Erlang
1> Secret = "this is our super secret key; only we should know it".
"this is our super secret key; only we should know it"
2> Public = "we used our secret key".
"we used our secret key"
3> Location = "http://mybank/".
"http://mybank/"
4> {ok, M} = macaroon:create(Location, Secret, Public).
{ok,{macaroon,<<>>}}
```

We've created our first macaroon!

You can see here that it took three pieces of information to create a macaroon.
We start with a secret.  Here, we just have English text, but in reality we
would want to use something more random and less predictable (see below for a
suggestion on how to generate one).  The public portion tells us which secret we
used to create the macaroon, but doesn't give anyone else a clue as to the
contents of the secret.  Anyone in possession of the macaroon can see the public
portion:

```Erlang
5> macaroon:identifier(M).
{ok,<<"we used our secret key">>}
```

This public portion, known as the macaroon's identifier, can be anything that
enables us to remember our secret.  In this example, we know that the string 'we
used our secret key' always refers to this secret.  We could just as easily keep
a database mapping public macaroon identities to private secrets, or encrypt the
public portion using a key known only to us.  The only requirement here is that
our application be able to remember the secret given the public portion, and
that no one else is able to guess the secret.

Our macaroon includes some additional information that enables us to add caveats
and figure out where the macaroon should be used.  The macaroon's location gives
a hint to the user about where the macaroon is accepted for authorization.  This
hint is a free-form string maintained to help applications figure out where to
use macaroons; the libmacaroons library (and by extension, the Erlang wrapper)
does not ascribe any meaning to this location.

Each macaroon also has a signature that is the key used to add caveats and
verify the macaroon.  The signature is computed by the macaroons library, and is
unique to each macaroon.  Applications should never need to directly work with
the signature of the macaroon.  Any entity in possession of the macaroon's
signature should be assumed to possess the macaroon itself.

Both of these pieces of information are publicly accessible:

```Erlang
6> macaroon:location(M).
{ok,<<"http://mybank/">>}
7> macaroon:signature(M).
{ok,<<227,217,224,41,8,82,108,76,0,57,174,21,17,65,21,
      217,127,221,104,191,43,163,121,179,66,170,240,...>>}
```

We can share this macaroon with others by serializing it.  The serialized form
is pure-ASCII, and is safe for inclusion in secure email, a standard HTTPS
cookie, or a URL.   We can get the serialized form with:

```Erlang
8> macaroon:serialize(M).
{ok,<<"MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj"...>>}
```

Of course, this serialized form can be displayed in a more human-readable form
for easy debugging:

```Erlang
9> {ok, InspectData} = macaroon:inspect(M).
{ok,<<"location http://mybank/\nidentifier we used our secret key\nsignature e3d9e02908526c4c0039ae15114115d97fdd68bf"...>>}
10> io:format([InspectData, "\n"]).
location http://mybank/
identifier we used our secret key
signature e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f
ok
```

Adding Caveats
--------------

At this point, we have an unconstrained macaroon that authorizes everything
within our bank.  In practice, such a macaroon is dangerous, because very few
people should hold such power.  Let's add a caveat to our macaroon that
restricts it to just the account number 3735928559.

```Erlang
11> macaroon:add_first_party_caveat(M, "account = 3735928559").
{ok,{macaroon,<<>>}}
```

This new macaroon includes the same identifier and location that our old
macaroon from our initial macaroon, but includes the additional caveat that
restricts the bank account.  The signature of this new macaroon is different,
and incorporates the new caveat we've just added.  An entity in possession of
this new macaroon cannot simply remove our new caveat to construct the old
macaroon:

```Erlang
12> {ok, M2} = macaroon:add_first_party_caveat(M, "account = 3735928559").
{ok,{macaroon,<<>>}}
13> {ok, InspectData2} = macaroon:inspect(M2).
{ok,<<"location http://mybank/\nidentifier we used our secret key\ncid account = 3735928559\nsignature 1efe4763f290dbc"...>>}
14> io:format([InspectData2, "\n"]).
location http://mybank/
identifier we used our secret key
cid account = 3735928559
signature 1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128
ok
```

Of course, we can add a few more caveats, and the macaroon's signature will
change with each of them.

```Erlang
15> {ok, M3} = macaroon:add_first_party_caveat(M2, "time < 2020-01-01T00:00").
{ok,{macaroon,<<>>}}
16> macaroon:signature(M3).
{ok,<<181,240,108,140,142,249,47,108,130,198,255,40,44,
      209,248,189,24,73,48,29,9,162,219,99,75,161,130,...>>}
17> {ok, M4} = macaroon:add_first_party_caveat(M3, "email = alice@example.org").
{ok,{macaroon,<<>>}}
18> macaroon:signature(M4).
{ok,<<221,245,83,228,96,131,229,91,141,113,171,130,43,
      227,216,252,242,29,107,241,156,64,214,23,187,159,
      180,...>>}
19> {ok, InspectData4} = macaroon:inspect(M4).
{ok,<<"location http://mybank/\nidentifier we used our secret key\ncid account = 3735928559\ncid time < 2020-01-01T00:"...>>}
20> io:format([InspectData4, "\n"]).
location http://mybank/
identifier we used our secret key
cid account = 3735928559
cid time < 2020-01-01T00:00
cid email = alice@example.org
signature ddf553e46083e55b8d71ab822be3d8fcf21d6bf19c40d617bb9fb438934474b6
ok
```

The combination of all caveats in this macaroon authorize alice@example.org to
access account 3735928559 until the end of 2019.  Alice may present this
macaroon to the bank any time she wishes to prove to the bank that she is
authorized to access her account.  Ideally, she'll transmit the serialized form
of the macaroon to the bank:

```Erlang
25> {ok, Msg} = macaroon:serialize(M4).
{ok,<<"MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50"...>>}
26> % send msg to the bank
```

Verifying Macaroons
-------------------

Our bank application's purpose is to protect users accounts from unauthorized
access.  For that reason, it cannot just accept anything that looks like a
macaroon---that would defeat the point of using macaroons in the first place.
So how can we ensure that only authorized users access the bank?

We can determine whether a request is authorized through a process called
verification.  First, we construct a verifier that can determine whether the
caveats on macaroons are satisfied.  We can then use our verifier to determine
whether a given macaroon is authorized in the context of the request.  For
example, our bank account application knows the account number specified in the
request, and can specify `account = #` when building the verifier.  The
verifier can then check that this matches the information within the macaroon,
and authorize the macaroon if it does indeed match.

Let's walk through the verification process for Alice's macaroon that we
constructed in the previous section.  The first step, of course, is for the bank
to deserialize the macaroon from the message.  This converts the macaroon into a
form we can work with.

```Erlang
2> {ok, M} = macaroon:deserialize(Msg).
{ok,{macaroon,<<>>}}
3> {ok, InspectData} = macaroon:inspect(M).
{ok,<<"location http://mybank/\nidentifier we used our secret key\ncid account = 3735928559\ncid time < 2020-01-01T00:"...>>}
4> io:format([InspectData, "\n"]).
location http://mybank/
identifier we used our secret key
cid account = 3735928559
cid time < 2020-01-01T00:00
cid email = alice@example.org
signature ddf553e46083e55b8d71ab822be3d8fcf21d6bf19c40d617bb9fb438934474b6
ok
```

We have the same macaroon that Alice believes authorizes her to access her own
account, but we must verify this for ourselves.  One (very flawed) way we could
try to verify this macaroon would be to manually parse it and authorize the
request if its caveats are true.  But handling things this way completely
sidesteps all the crypto-goodness that macaroons are built upon.

Another approach to verification would be to use libmacaroons's built-in
verifier to process the macaroon.  The verifier hides many of the details of the
verification process, and provides a natural way to work with many kinds of
caveats.  The verifier itself is constructed once, and may be re-used to verify
multiple macaroons.

```Erlang
5> {ok, V} = macaroon_verifier:create().
{ok,{verifier,<<>>}}
```

Let's go ahead and try to verify the macaroon to see if the request is
authorized.  To verify the request, we need to provide the verifier with Alice's
macaroon, and the secret that was used to construct it.  In a real application,
we would retrieve the secret using `macaroon:identifier(M)`; here, we know the
secret and provide it directly.  A verifier can only ever successfully verify
the macaroon when provided with the macaroon and its corresponding secret---no
secret, no authorization.

Intuitively, our verifier should say that this macaroon is unauthorized because
our verifier cannot prove that any of the caveats we've added are satisfied.  We
can see that it fails just as we would expect:

```Erlang
6> macaroon_verifier:verify(V, M, Secret).
{error,not_authorized}
```

We can inform the verifier of the caveats used by our application using two
different techniques.  The first technique is to directly provide the verifier
with the caveats that match the context of the request.  For example, every
account-level action in a typical banking application is performed by a specific
user and targets a specific account.  This information is fixed for each
request, and is known at the time of the request.  We can tell the verifier
directly about these caveats like so:

```Erlang
7> macaroon_verifier:satisfy_exact(V, "account = 3735928559").
ok
8> macaroon_verifier:satisfy_exact(V, "email = alice@example.org").
ok
```

Caveats like these are called *exact caveats* because there is exactly one way
to satisfy them.  Either the account number is 3735928559, or it isn't.  At
verification time, the verifier will check each caveat in the macaroon against
the list of satisfied caveats provided to ``satisfyExact''.  When it finds a
match, it knows that the caveat holds and it can move onto the next caveat in
the macaroon.

Generally, you will specify multiple true statements as exact caveats, and let
the verifier decide which are relevant to each macaroon at verification time.
If you provide all exact caveats known to your application to the verifier, it
becomes trivial to change policy decisions about authorization.  The server
performing authorization can treat the verifier as a black-box and does not need
to change when changing the authorization policy.  The actual policy is enforced
when macaroons are minted and when caveats are embedded.  In our banking
example, we could provide some additional satisfied caveats to the verifier,
to describe some (or all) of the properties that are known about the current
request.  In this manner, the verifier can be made more general, and be
"future-proofed", so that it will still function correctly even if somehow  
the authorization policy for Alice changes; for example, by adding the three
following facts, the verifier will continue to work even if Alice decides to
self-attenuate her macaroons to be only usable from her IP address and browser:

```Erlang
9> macaroon_verifier:satisfy_exact(V, "IP = 127.0.0.1").
ok
10> macaroon_verifier:satisfy_exact(V, "browser = Chrome").
ok
11> macaroon_verifier:satisfy_exact(V, "action = deposit").
ok
```

Although it's always possible to satisfy a caveat within a macaroon by providing
it directly to the verifier, doing so can be quite tedious.  Consider the caveat
on access time embedded within Alice's macaroon.  While an authorization routine
could provide the exact caveat `time < 2020-01-01T00:00`, doing so would
require inspecting the macaroon before building the verifier.  Just like using
MD5 to hash passwords, inspecting a macaroon's structure to build a verifier for
it is considered to be very bad practice, and should be violently demonized in
Hacker News discussions with vague, slightly inaccurate allusions to pbkdf2.

So how can we tell our verifier that the caveat on access time is satisfied?  We
could provide many exact caveats of the form `time < YYYY-mm-ddTHH:MM`, but
this reeks of inefficiency. The second technique for satisfying caveats provides
a more general solution.

Called *general caveats*, the second technique for informing the verifier that
a caveat is satisfied allows for expressive caveats.  Whereas exact caveats are
checked by simple byte-wise equality, general caveats are checked using an
application-provided callback that returns true if and only if the caveat is
true within the context of the request.  There's no limit on the contents of a
general caveat, so long as the callback understands how to determine whether it
is satisfied.

We can verify the time caveat on Alice's macaroon by writing a function that
checks the current time against the time specified by the caveat (the example
uses [qdate][4] library for date operations):

```Erlang
12> CheckTime =
12>     fun
12>         (<<"time < ", Date/binary>>) ->
12>             qdate:compare(erlang:now(), '<=', Date);
12>         (_) ->
12>             false
12>     end.
#Fun<erl_eval.6.90072148>
```

This callback processes all caveats that begin with `time < `, and returns
`true` if the specified time has not yet passed.  We can see that our caveat
does indeed return `true` when the caveat holds, and `false` otherwise:

```Erlang
13> CheckTime(<<"time < 2020-01-01T00:00">>).
true
14> CheckTime(<<"time < 2014-01-01T00:00">>).
false
15> CheckTime(<<"account = 3735928559">>).
false
```

We can provide the `CheckTime` function directly to the verifier, so that it
may check time-based predicates.

```Erlang
16> macaroon_verifier:satisfy_general(V, CheckTime).
ok
```

It's finally time to verify our macaroon!  Now that we've informed the verifier
of all the various caveats that our application could embed within a macaroon,
we can expect that the verification step will succeed.

```Erlang
17> macaroon_verifier:verify(V, M, Secret).
ok
```

More importantly, the verifier will also work for macaroons we've not yet seen,
like one that only permits Alice to deposit into her account:

```Erlang
18> {ok, N} = macaroon:add_first_party_caveat(M, "action = deposit").
{ok,{macaroon,<<>>}}
19> macaroon_verifier:verify(V, N, Secret).
ok
```

Equally important is the verifier's ability to reject improper macaroons because
they are not authorized.  An improper macaroon could have additional caveats not
known to the verifier, or have false general caveats.  Worse, an unauthorized
macaroon could be an attempt by a determined attacker to break into our bank.
The verifier we've built will reject all of these scenarios:

```Erlang
20> % Unknown caveat
20> {ok, N2} = macaroon:add_first_party_caveat(M, "OS = Windows XP").
{ok,{macaroon,<<>>}}
21> macaroon_verifier:verify(V, N2, Secret).
{error,not_authorized}
22> 
22> % False caveat
22> {ok, N3} = macaroon:add_first_party_caveat(M, "time < 2014-01-01T00:00").
{ok,{macaroon,<<>>}}
23> macaroon_verifier:verify(V, N3, Secret).
{error,not_authorized}
24>
24> % Bad secret
24> macaroon_verifier:verify(V, M, "this is not the secret we were looking for").
{error,not_authorized}
25>
25> % Incompetent hackers trying to change the signature
25> {ok, N4} = macaroon:deserialize(<<"MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNl\nY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDIwY2lkIHRpbWUgPCAyMDIw\nLTAxLTAxVDAwOjAwCjAwMjJjaWQgZW1haWwgPSBhbGljZUBleGFtcGxlLm9yZwowMDJmc2lnbmF0\ndXJlID8f19FL+bkC9p/aoMmIecC7GxdOcLVyUnrv6lJMM7NSCg==\n">>).
{ok,{macaroon,<<>>}}
26> {ok, InspectData4} = macaroon:inspect(N4).
{ok,<<"location http://mybank/\nidentifier we used our secret key\ncid account = 3735928559\ncid time < 2020-01-01T00:"...>>}
27> io:format([InspectData4, "\n"]).
location http://mybank/
identifier we used our secret key
cid account = 3735928559
cid time < 2020-01-01T00:00
cid email = alice@example.org
signature 3f1fd7d14bf9b902f69fdaa0c98879c0bb1b174e70b572527aefea524c33b352
ok
28> macaroon:signature(M) =:= macaroon:signature(N).
false
29> macaroon_verifier:verify(V, N4, Secret).
{error,not_authorized}
```

Using Third-Party Caveats
-------------------------

Like first-party caveats, third-party caveats restrict the context in which a
macaroon is authorized, but with a different form of restriction.  Where a
first-party caveat is checked directly within the verifier, a third-party caveat
is checked by the third-party, who provides a discharge macaroon to prove that
the original third-party caveat is true.  The discharge macaroon is recursively
inspected by the verifier; if it verifies successfully, the discharge macaroon
serves as a proof that the original third-party caveat is satisfied.  Of course,
nothing stops discharge macaroons from containing embedded first- or third-party
caveats for the verifier to consider during verification.

Let's rework the above example to provide Alice with access to her account only
after she authenticates with a service that is separate from the service
processing her banking transactions.

As before, we'll start by constructing a new macaroon with the caveat that is
limited to Alice's bank account.

```Erlang
1> Secret = "this is a different super-secret key; never use the same secret twice".
"this is a different super-secret key; never use the same secret twice"
2> Public = "we used our other secret key".
"we used our other secret key"
3> Location = "http://mybank/".
"http://mybank/"
4> {ok, M} = macaroon:create(Location, Secret, Public).
{ok,{macaroon,<<>>}}
5> {ok, M2} = macaroon:add_first_party_caveat(M, "account = 3735928559").
{ok,{macaroon,<<>>}}
6> {ok, InspectData2} = macaroon:inspect(M2).
{ok,<<"location http://mybank/\nidentifier we used our other secret key\ncid account = 3735928559\nsignature 1434e674a"...>>}
7> io:format([InspectData2, "\n"]).
location http://mybank/
identifier we used our other secret key
cid account = 3735928559
signature 1434e674ad84fdfdc9bc1aa00785325c8b6d57341fc7ce200ba4680c80786dda
ok
```

So far, so good.  Now let's add a third party caveat to this macaroon that
requires that Alice authenticate with `http://auth.mybank/` before being
authorized access to her account.  To add a third-party caveat we'll need to
specify a location hint, generate a secret, and somehow be able to identify this
secret later.  Like the location used when creating a macaroon, the location
used when adding a third-party caveat is simply a hint to the application that
is uninterpreted by libmacaroons.

The secret and identity are handled differently than during creation, however,
because they need to be known to the third party.  To do this, we'll provide the
third-party with a randomly generated `CaveatKey` and the predicate we wish
for it to check.  In response, it will give us an identifier that we can embed
within the macaroon.  Later, when we need to construct a discharge macaroon, we
can provide it with just this identifier, from which it can recall the key and
predicate to check.

Here's what this looks like in code:

```Erlang
8> % you'll likely want to use a higher entropy source to generate this key
8> CaveatKey = "4; guaranteed random by a fair toss of the dice".
"4; guaranteed random by a fair toss of the dice"
9> Predicate = "user = Alice".
"user = Alice"
10> % send_to_auth(CaveatKey, Predicate).
10> % Identifier = recv_from_auth().
10> Identifier = "this was how we remind auth of key/pred".
"this was how we remind auth of key/pred"
11> {ok, M3} = macaroon:add_third_party_caveat(M2, "http://auth.mybank/", CaveatKey, Identifier).
{ok,{macaroon,<<>>}}
12> {ok, InspectData3} = macaroon:inspect(M3).
{ok,<<"location http://mybank/\nidentifier we used our other secret key\ncid account = 3735928559\ncid this was how we"...>>}
13> io:format([InspectData3, "\n"]).
location http://mybank/
identifier we used our other secret key
cid account = 3735928559
cid this was how we remind auth of key/pred
vid Yafxa0nawoGwaaW7jnXFdokcQzpJX2_IbCE-rmmnnn0ykx9godTBSexebYN5Zy2Lcc5IgqrEXG4BnvK_l-naGafwLFqF4C5t
cl http://auth.mybank/
signature f1c7e8c009e2fb3fec2da107e2bd8b97f1041cd06e8ec1b4c681000f5fee4a28
ok
```

We now have a macaroon with a third-party caveat.  The most interesting thing to
note about this macaroon is that it includes no information that reveals the
predicate it encodes.  The third-party service knows the key and the predicate,
and internally associates them with the identifier, but the identifier itself is
arbitrary and betrays no information about the predicate to others.  The service
at `http://auth.mybank/` can authenticate that the user is Alice, and provide
proof that the caveat is satisfied, without revealing Alice's identity.  Other
services can verify M and its associated discharge macaroon, without knowing the
predicates the third-parties verified.

The process for discharging third party caveats starts with the holder of the
initial root macaroon, Alice.  Alice looks at the macaroon for the list of third
party caveat (location, identifier) pairs that must be addressed.

```Erlang
14> macaroon:third_party_caveats(M3).
{ok,[{<<"http://auth.mybank/">>,
      <<"this was how we remind auth of key/pred">>}]}
```

In a real application, we'd look at these third party caveats, and contact each
location to retrieve the requisite discharge macaroons.  We would include the
identifier for the caveat in the request itself, so that the server can recall
the secret used to create the third-party caveat.  The server can then generate
and return a new macaroon that discharges the caveat:

```Erlang
15> {ok, D} = macaroon:create("http://auth.mybank/", CaveatKey, Identifier).
{ok,{macaroon,<<>>}}
16> {ok, D2} = macaroon:add_first_party_caveat(D, "time < 2020-01-01T00:00").
{ok,{macaroon,<<>>}}
17> {ok, DInspectData2} = macaroon:inspect(D2).
{ok,<<"location http://auth.mybank/\nidentifier this was how we remind auth of key/pred\ncid time < 2020-01-01T00:00\n"...>>}
18> io:format([DInspectData2, "\n"]).
location http://auth.mybank/
identifier this was how we remind auth of key/pred
cid time < 2020-01-01T00:00
signature 2ed1049876e9d5840950274b579b0770317df54d338d9d3039c7c67d0d91d63c
ok
```

This new macaroon enables the verifier to determine that the third party caveat
is satisfied.  Our target service added a time-limiting caveat to this macaroon
that ensures that this discharge macaroon does not last forever.  This ensures
that Alice (or, at least someone authenticated as Alice) cannot use the
discharge macaroon indefinitely and will eventually have to re-authenticate.

Once Alice has both the root macaroon and the discharge macaroon in her
possession, she can make the request to the target service.  Making a request
with discharge macaroons is only slightly more complicated than making requests
with a single macaroon.  In addition to serializing and transmitting all
involved macaroons, there is preparation step that binds the discharge macaroons
to the root macaroon.  This binding step ensures that the discharge macaroon is
useful only when presented alongside the root macaroon.  The root macaroon is
used to bind the discharge macaroons like this:

```Erlang
19> {ok, DP} = macaroon:prepare_for_request(M3, D2).
{ok,{macaroon,<<>>}}
```

If we were to look at the signatures on these prepared discharge macaroons, we
would see that the binding process has irreversibly altered their signature(s).

```Erlang
20> macaroon:signature(D2).
{ok,<<46,209,4,152,118,233,213,132,9,80,39,75,87,155,7,
      112,49,125,245,77,51,141,157,48,57,199,198,...>>}
21> macaroon:signature(DP).
{ok,<<234,59,67,200,81,76,30,233,62,183,214,135,21,212,
      146,202,97,7,39,115,26,142,122,62,99,183,76,...>>}
```

The root macaroon `M3` and its discharge macaroons `DP` are ready for the
request.  Alice can serialize them all and send them to the bank to prove she is
authorized to access her account.  The bank can verify them using the same
verifier we built before.  We provide the discharge macaroons as a third
argument to the verify call:

```Erlang
23> macaroon_verifier:verify(V, M3, Secret, [DP]).
ok
```

Without the `prepareForRequest` call, the verification would fail:

```Erlang
24> macaroon_verifier:verify(V, M3, Secret, [D2]).
{error,not_authorized}
```

Choosing Secrets
----------------

For clarity, we've generated human-readable secrets that we use as the root keys
of all of our macaroons.  In practice, this is terribly insecure and can lead to
macaroons that can easily be forged because the secret is too predictable.  To
avoid this, we recommend generating secrets using a sufficient number of
suitably random bytes.  Because the bytes are a secret key, they should be drawn
from a source with enough entropy to ensure that the key cannot be guessed
before the macaroon falls out of use.

The `macaroon` module exposes a constant that is the ideal number of bytes
these secret keys should contain.  Any shorter is wasting an opportunity for
security.

```Erlang
1> macaroon:suggested_secret_length().
32
```

Third-Party Caveats with Public Keys
------------------------------------

Public key cryptography can enable much more efficient schemes for adding
third-party caveats.  In the above example where we added a third-party caveat,
the caveat's identifier was generated by the third party and retrieved with in
one round trip.  We can eliminate the round trip when the third party has a
well-known public key.  We can encrypt the caveat's secret, and the predicate to
be checked using this public key, and use the ciphertext directly as the
caveat's identifier.  This saves a round trip, and frees the third party from
having to remember an association between identifiers and key/predicate pairs.

[1]: https://github.com/rescrv/libmacaroons/blob/ca1e875b06862e6cd515a4e3c0e5b124ef502366/README
[2]: https://github.com/rescrv/libmacaroons
[3]: http://research.google.com/pubs/pub41892.html
[4]: https://github.com/choptastic/qdate
[5]: https://github.com/jedisct1/libsodium
[6]: https://github.com/rebar/rebar
