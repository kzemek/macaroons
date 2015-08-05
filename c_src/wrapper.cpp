#include "nifpp.h"
#include "macaroons.h"

#include <algorithm>
#include <cstring>
#include <forward_list>
#include <future>
#include <memory>
#include <thread>
#include <tuple>
#include <vector>

#define NIF_FUNCTION(NAME)                                                     \
    static ERL_NIF_TERM NAME##_nif(                                            \
        ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])               \
    {                                                                          \
        return wrap(NAME, env, argv);                                          \
    }

struct Env {
    Env()
        : e{enif_alloc_env()}
    {
        if (!e)
            throw std::bad_alloc{};
    }

    ~Env() { enif_free_env(e); }

    operator ErlNifEnv *() { return e; }

    ErlNifEnv *e;
};

struct Verifier {
    Verifier()
        : v{macaroon_verifier_create()}
    {
        if (!v)
            throw std::bad_alloc{};
    }

    ~Verifier()
    {
        if (v)
            macaroon_verifier_destroy(v);
    }

    operator struct macaroon_verifier *() { return v; }

    Env env;
    std::forward_list<nifpp::TERM> funs;

    struct macaroon_verifier *v;
};

struct Macaroon {
    Macaroon(struct macaroon *m_)
        : m{m_}
    {
    }

    ~Macaroon()
    {
        if (m)
            macaroon_destroy(m);
    };

    operator struct macaroon *() { return m; }

    struct macaroon *m;
};

namespace {
thread_local ErlNifPid s_pid;
thread_local nifpp::TERM s_ref;

extern "C" int generalCheck(void *f, const unsigned char *pred, size_t pred_sz)
{
    nifpp::binary predicate{pred_sz};
    std::copy(pred, pred + pred_sz, predicate.data);

    auto promise = nifpp::construct_resource<std::promise<bool>>();
    auto future = promise->get_future();

    Env env;
    nifpp::TERM fun{enif_make_copy(env, *static_cast<nifpp::TERM *>(f))};
    nifpp::TERM ref{enif_make_copy(env, s_ref)};

    auto message =
        nifpp::make(env, std::make_tuple(ref, fun, nifpp::make(env, promise),
                             nifpp::make(env, predicate)));

    enif_send(nullptr, &s_pid, env, message);
    return future.get() ? 0 : -1;
}

nifpp::TERM translateError(
    ErlNifEnv *const env, const enum macaroon_returncode err)
{
    nifpp::str_atom reason;

    switch (err) {
        case MACAROON_BUF_TOO_SMALL:
            reason = "buffer_too_small";
            break;
        case MACAROON_CYCLE:
            reason = "discharge_caveats_form_a_cycle";
            break;
        case MACAROON_HASH_FAILED:
            reason = "hmac_function_failed";
            break;
        case MACAROON_NOT_AUTHORIZED:
            reason = "not_authorized";
            break;
        case MACAROON_NO_JSON_SUPPORT:
            reason = "json_macaroons_not_supported";
            break;
        case MACAROON_TOO_MANY_CAVEATS:
            reason = "too_many_caveats";
            break;
        case MACAROON_INVALID:
            reason = "macaroon_invalid";
            break;
        case MACAROON_OUT_OF_MEMORY:
            throw std::bad_alloc{};
        default:
            reason = "unknown_error";
            break;
    }

    return nifpp::make(env, std::make_tuple(nifpp::str_atom{"error"}, reason));
}

nifpp::TERM ret(
    ErlNifEnv *const env, nifpp::TERM term, const enum macaroon_returncode err)
{
    if (err != MACAROON_SUCCESS)
        return translateError(env, err);

    return nifpp::make(env, std::make_tuple(nifpp::str_atom{"ok"}, term));
}

nifpp::TERM ret(ErlNifEnv *const env, const enum macaroon_returncode err)
{
    if (err != MACAROON_SUCCESS)
        return translateError(env, err);

    return nifpp::make(env, nifpp::str_atom{"ok"});
}

template <typename... Args, std::size_t... I>
ERL_NIF_TERM wrapHelper(ERL_NIF_TERM (*fun)(ErlNifEnv *, Args...),
    ErlNifEnv *env, const ERL_NIF_TERM args[], std::index_sequence<I...>)
{
    try {
        return fun(env, nifpp::get<Args>(env, args[I])...);
    }
    catch (const nifpp::badarg &) {
        return enif_make_badarg(env);
    }
    catch (const std::exception &e) {
        return nifpp::make(env,
            std::make_tuple(nifpp::str_atom{"error"}, std::string{e.what()}));
    }
}

template <typename... Args>
ERL_NIF_TERM wrap(ERL_NIF_TERM (*fun)(ErlNifEnv *, Args...), ErlNifEnv *env,
    const ERL_NIF_TERM args[])
{
    return wrapHelper(fun, env, args, std::index_sequence_for<Args...>{});
}

ERL_NIF_TERM createMacaroon(
    ErlNifEnv *env, ErlNifBinary location, ErlNifBinary key, ErlNifBinary id)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    auto M = nifpp::construct_resource<Macaroon>(macaroon_create(location.data,
        location.size, key.data, key.size, id.data, id.size, &err));

    return ret(env, nifpp::make(env, M), err);
}

ERL_NIF_TERM addFirstPartyCaveat(
    ErlNifEnv *env, Macaroon *mp, ErlNifBinary predicate)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    auto M =
        nifpp::construct_resource<Macaroon>(macaroon_add_first_party_caveat(
            *mp, predicate.data, predicate.size, &err));

    return ret(env, nifpp::make(env, M), err);
}

ERL_NIF_TERM addThirdPartyCaveat(ErlNifEnv *env, Macaroon *mp,
    ErlNifBinary location, ErlNifBinary key, ErlNifBinary id)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    auto M = nifpp::construct_resource<Macaroon>(
        macaroon_add_third_party_caveat(*mp, location.data, location.size,
            key.data, key.size, id.data, id.size, &err));

    return ret(env, nifpp::make(env, M), err);
}

ERL_NIF_TERM thirdPartyCaveats(ErlNifEnv *env, Macaroon *mp)
{
    const auto caveatsNum = macaroon_num_third_party_caveats(*mp);
    std::vector<nifpp::TERM> caveats;
    caveats.reserve(caveatsNum);

    for (auto i = 0u; i < caveatsNum; ++i) {
        const unsigned char *locationData = NULL, *idData = NULL;
        std::size_t locationSize = 0, idSize = 0;

        if (macaroon_third_party_caveat(
                *mp, i, &locationData, &locationSize, &idData, &idSize) != 0)
            return translateError(
                env, static_cast<enum macaroon_returncode>(-1));

        nifpp::binary location{locationSize};
        std::copy(locationData, locationData + locationSize, location.data);

        nifpp::binary id{idSize};
        std::copy(idData, idData + idSize, id.data);

        caveats.emplace_back(nifpp::make(env,
            std::make_tuple(nifpp::make(env, location), nifpp::make(env, id))));
    }

    return nifpp::make(env, std::make_tuple(nifpp::str_atom{"ok"}, caveats));
}

ERL_NIF_TERM prepareForRequest(ErlNifEnv *env, Macaroon *mp, Macaroon *dp)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    auto M = nifpp::construct_resource<Macaroon>(
        macaroon_prepare_for_request(*mp, *dp, &err));

    return ret(env, nifpp::make(env, M), err);
}

ERL_NIF_TERM createVerifier(ErlNifEnv *env)
{
    auto V = nifpp::construct_resource<Verifier>();
    return ret(env, nifpp::make(env, V), MACAROON_SUCCESS);
}

ERL_NIF_TERM satisfyExact(ErlNifEnv *env, Verifier *vp, ErlNifBinary predicate)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    macaroon_verifier_satisfy_exact(*vp, predicate.data, predicate.size, &err);
    return ret(env, err);
}

ERL_NIF_TERM satisfyGeneral(ErlNifEnv *env, Verifier *vp, nifpp::TERM fun)
{
    vp->funs.emplace_front();

    enum macaroon_returncode err = MACAROON_SUCCESS;
    macaroon_verifier_satisfy_general(
        *vp, generalCheck, &vp->funs.front(), &err);

    if (err != MACAROON_SUCCESS)
        vp->funs.pop_front();
    else
        vp->funs.front() = nifpp::TERM{enif_make_copy(vp->env, fun)};

    return ret(env, err);
}

ERL_NIF_TERM startVerifyThread(ErlNifEnv *env, Verifier *vp, Macaroon *mp,
    ErlNifBinary key, std::vector<Macaroon *> dischargeMacaroons,
    nifpp::TERM ref)
{
    auto thread = nifpp::construct_resource<std::thread>([=]() mutable {
        Env localEnv;
        enif_self(env, &s_pid);
        s_ref = nifpp::TERM{enif_make_copy(localEnv, ref)};

        std::vector<struct macaroon *> macaroons;
        std::transform(dischargeMacaroons.begin(), dischargeMacaroons.end(),
            std::back_inserter(macaroons), [](Macaroon *m) { return m->m; });

        enum macaroon_returncode err = MACAROON_SUCCESS;
        macaroon_verify(*vp, *mp, key.data, key.size, macaroons.data(),
            macaroons.size(), &err);

        nifpp::TERM msg{enif_make_copy(localEnv, ret(localEnv, err))};
        enif_send(nullptr, &s_pid, localEnv,
            nifpp::make(localEnv,
                      std::make_tuple(s_ref, nifpp::str_atom{"done"}, msg)));
    });

    return nifpp::make(env, thread);
}

ERL_NIF_TERM joinVerifyThread(ErlNifEnv *env, std::thread *thread)
{
    if (thread->joinable())
        thread->join();

    return ret(env, MACAROON_SUCCESS);
}

ERL_NIF_TERM setVerifyStatus(
    ErlNifEnv *env, std::promise<bool> *promise, bool status)
{
    promise->set_value(status);
    return ret(env, MACAROON_SUCCESS);
}

ERL_NIF_TERM returnBinary(ErlNifEnv *env, Macaroon &m,
    void (*saveData)(const struct macaroon *, const unsigned char **, size_t *))
{
    const unsigned char *data = nullptr;
    std::size_t dataSize = 0;

    saveData(m, &data, &dataSize);
    nifpp::binary bin{dataSize};
    std::copy(data, data + dataSize, bin.data);

    return ret(env, nifpp::make(env, bin), MACAROON_SUCCESS);
}

ERL_NIF_TERM returnBinary(ErlNifEnv *env, Macaroon &m,
    size_t (*sizeHint)(const struct macaroon *),
    int (*saveData)(const struct macaroon *, char *, size_t,
                              enum macaroon_returncode *))
{
    auto size = sizeHint(m);
    nifpp::binary bin{size};

    enum macaroon_returncode err = MACAROON_SUCCESS;
    saveData(m, reinterpret_cast<char *>(bin.data), bin.size, &err);
    while (err == MACAROON_BUF_TOO_SMALL) {
        size *= 2;
        enif_realloc_binary(&bin, size);
        saveData(m, reinterpret_cast<char *>(bin.data), bin.size, &err);
    }

    if (err != MACAROON_SUCCESS)
        return ret(env, err);

    const auto realSize = std::strlen(reinterpret_cast<char *>(bin.data));
    if (size != realSize)
        enif_realloc_binary(&bin, realSize);

    return ret(env, nifpp::make(env, bin), MACAROON_SUCCESS);
}

ERL_NIF_TERM location(ErlNifEnv *env, Macaroon *m)
{
    return returnBinary(env, *m, macaroon_location);
}

ERL_NIF_TERM identifier(ErlNifEnv *env, Macaroon *m)
{
    return returnBinary(env, *m, macaroon_identifier);
}

ERL_NIF_TERM signature(ErlNifEnv *env, Macaroon *m)
{
    return returnBinary(env, *m, macaroon_signature);
}

ERL_NIF_TERM serialize(ErlNifEnv *env, Macaroon *m)
{
    return returnBinary(
        env, *m, macaroon_serialize_size_hint, macaroon_serialize);
}

ERL_NIF_TERM deserialize(ErlNifEnv *env, std::string bin)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    auto m = nifpp::construct_resource<Macaroon>(
        macaroon_deserialize(bin.c_str(), &err));
    return ret(env, nifpp::make(env, m), err);
}

ERL_NIF_TERM inspect(ErlNifEnv *env, Macaroon *m)
{
    return returnBinary(env, *m, macaroon_inspect_size_hint, macaroon_inspect);
}

ERL_NIF_TERM copy(ErlNifEnv *env, Macaroon *m)
{
    enum macaroon_returncode err = MACAROON_SUCCESS;
    auto copyM = nifpp::construct_resource<Macaroon>(macaroon_copy(*m, &err));
    return ret(env, nifpp::make(env, copyM), err);
}

ERL_NIF_TERM compare(ErlNifEnv *env, Macaroon *m, Macaroon *n)
{
    return nifpp::make(env, macaroon_cmp(*m, *n) == 0);
}

ERL_NIF_TERM maxStrlen(ErlNifEnv *env)
{
    return nifpp::make(env, MACAROON_MAX_STRLEN);
}

ERL_NIF_TERM maxCaveats(ErlNifEnv *env)
{
    return nifpp::make(env, MACAROON_MAX_CAVEATS);
}

ERL_NIF_TERM suggestedSecretLength(ErlNifEnv *env)
{
    return nifpp::make(env, MACAROON_SUGGESTED_SECRET_LENGTH);
}

extern "C" {

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    nifpp::register_resource<Macaroon>(env, "macaroons_nif", "macaroon");
    nifpp::register_resource<Verifier>(env, "macaroons_nif", "verifier");
    nifpp::register_resource<std::thread>(env, "macaroons_nif", "thread");
    nifpp::register_resource<std::promise<bool>>(
        env, "macaroons_nif", "promise");

    return 0;
}

NIF_FUNCTION(createMacaroon)
NIF_FUNCTION(addFirstPartyCaveat)
NIF_FUNCTION(addThirdPartyCaveat)
NIF_FUNCTION(thirdPartyCaveats)
NIF_FUNCTION(prepareForRequest)
NIF_FUNCTION(createVerifier)
NIF_FUNCTION(satisfyExact)
NIF_FUNCTION(satisfyGeneral)
NIF_FUNCTION(startVerifyThread)
NIF_FUNCTION(joinVerifyThread)
NIF_FUNCTION(setVerifyStatus)
NIF_FUNCTION(location)
NIF_FUNCTION(identifier)
NIF_FUNCTION(signature)
NIF_FUNCTION(serialize)
NIF_FUNCTION(deserialize)
NIF_FUNCTION(inspect)
NIF_FUNCTION(copy)
NIF_FUNCTION(compare)
NIF_FUNCTION(maxStrlen)
NIF_FUNCTION(maxCaveats)
NIF_FUNCTION(suggestedSecretLength)

static ErlNifFunc nif_funcs[] = {{"create_macaroon", 3, createMacaroon_nif},
    {"add_first_party_caveat", 2, addFirstPartyCaveat_nif},
    {"add_third_party_caveat", 4, addThirdPartyCaveat_nif},
    {"third_party_caveats", 1, thirdPartyCaveats_nif},
    {"prepare_for_request", 2, prepareForRequest_nif},
    {"create_verifier", 0, createVerifier_nif},
    {"satisfy_exact", 2, satisfyExact_nif},
    {"satisfy_general", 2, satisfyGeneral_nif},
    {"start_verify_thread", 5, startVerifyThread_nif},
    {"join_verify_thread", 1, joinVerifyThread_nif},
    {"set_verify_status", 2, setVerifyStatus_nif},
    {"location", 1, location_nif}, {"identifier", 1, identifier_nif},
    {"signature", 1, signature_nif}, {"serialize", 1, serialize_nif},
    {"deserialize", 1, deserialize_nif}, {"inspect", 1, inspect_nif},
    {"copy", 1, copy_nif}, {"compare", 2, compare_nif},
    {"max_strlen", 0, maxStrlen_nif}, {"max_caveats", 0, maxCaveats_nif},
    {"suggested_secret_length", 0, suggestedSecretLength_nif}};

ERL_NIF_INIT(macaroons_nif, nif_funcs, load, NULL, NULL, NULL)

} // extern "C"
} // namespace
