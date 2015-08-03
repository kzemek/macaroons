#include "nifpp.h"
#include "macaroons.h"

#include <forward_list>
#include <future>
#include <memory>
#include <thread>
#include <tuple>
#include <vector>

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
} // namespace

extern "C" {

int general_check(void *f, const unsigned char *pred, size_t pred_sz)
{
    nifpp::binary predicate{pred_sz};
    std::copy(pred, pred + pred_sz, predicate.data);

    auto promise = nifpp::construct_resource<std::promise<bool>>();
    auto future = promise->get_future();

    Env env;
    nifpp::TERM fun{enif_make_copy(env, static_cast<nifpp::TERM *>(f))};
    nifpp::TERM ref{enif_make_copy(env, s_ref)};

    auto message = nifpp::make(
        env, std::make_tuple(ref, fun, nifpp::make(env, promise), predicate));

    enif_send(nullptr, &s_pid, env, message);
    return future.get();
}

} // extern "C"

namespace {

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
            return translate_error(env, -1);

        nifpp::binary location{locationSize};
        std::copy(locationData, locationData + locationSize, location.data);

        nifpp::binary id{idSize};
        std::copy(idData, idData + idSize, id.data);

        caveats.emplace_back(nifpp::make(env, std::make_tuple(location, id)));
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
        *vp, general_check, &vp->funs.front(), &err);

    if (err != MACAROON_SUCCESS)
        vp->funs.pop_front();
    else
        vp->funs.front() = enif_make_copy(vp->env, fun);

    return ret(env, err);
}

ERL_NIF_TERM verify(ErlNifEnv *env, Verifier *vp, Macaroon *mp,
    ErlNifBinary key, std::vector<Macaroon *> macaroons, nifpp::TERM ref)
{
    auto thread = nifpp::construct_resource<std::thread>([=] {
        Env localEnv;
        enif_self(env, &s_pid);
        s_ref = enif_make_copy(localEnv, ref);

        enum macaroon_returncode err = MACAROON_SUCCESS;
        macaroon_verify(*vp, *mp, key.data, key.size, macaroons.data(),
            macaroons.size(), &err);

        nifpp::TERM msg{enif_make_copy(localEnv, ret(env1, err))};
        enif_send(nullptr, &s_pid, localEnv,
            std::make_tuple(s_ref, nifpp::str_atom{"done"}, msg));
    });

    return nifpp::make(env, thread);
}

ERL_NIF_TERM join(ErlNifEnv *env, std::thread *thread)
{
    if (thread->joinable())
        thread->join();

    return ret(env, MACAROON_SUCCESS);
}

ERL_NIF_TERM verifyStatus(
    ErlNifEnv *env, std::promise<bool> *promise, bool status)
{
    promise->set_value(status);
    return ret(env, MACAROON_SUCCESS);
}

} // namespace

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

static ERL_NIF_TERM create_macaroon(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(createMacaroon, env, argv);
}

static ERL_NIF_TERM add_first_party_caveat(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(addFirstPartyCaveat, env, argv);
}

static ERL_NIF_TERM add_third_party_caveat(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(addThirdPartyCaveat, env, argv);
}

static ERL_NIF_TERM third_party_caveats(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(thirdPartyCaveats, env, argv);
}

static ERL_NIF_TERM prepare_for_request(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(prepareForRequest, env, argv);
}

static ERL_NIF_TERM create_verifier(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(createVerifier, env, argv);
}

static ERL_NIF_TERM satisfy_exact(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(satisfyExact, env, argv);
}

static ERL_NIF_TERM satisfy_general(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(satisfyGeneral, env, argv);
}

static ERL_NIF_TERM start_verify_thread(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(verify, env, argv);
}

static ERL_NIF_TERM join_verify_thread(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(join, env, argv);
}

static ERL_NIF_TERM set_verify_status(
    ErlNifEnv *env, int /*argc*/, const ERL_NIF_TERM argv[])
{
    return wrap(verifyStatus, env, argv);
}

static ErlNifFunc nif_funcs[] = {{"create_macaroon", 3, create_macaroon},
    {"add_first_party_caveat", 2, add_first_party_caveat},
    {"add_third_party_caveat", 4, add_third_party_caveat},
    {"third_party_caveats", 3, third_party_caveats},
    {"prepare_for_request", 2, prepare_for_request},
    {"create_verifier", 0, create_verifier},
    {"satisfy_exact", 2, satisfy_exact},
    {"satisfy_general", 2, satisfy_general},
    {"start_verify_thread", 5, start_verify_thread},
    {"join_verify_thread", 1, join_verify_thread},
    {"set_verify_status", 2, set_verify_status}};

ERL_NIF_INIT(macaroons_nif, nif_funcs, load, NULL, NULL, NULL)

} // extern "C"
