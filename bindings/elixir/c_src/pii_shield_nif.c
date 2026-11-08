/*
 * Erlang NIF shim wrapping the pii-ffi C-ABI (pii_shield.h).
 *
 * Erlang's :erlang.load_nif/2 requires erl_nif.h and ERL_NIF_INIT, so a bare
 * C-ABI .so cannot be loaded by the BEAM directly. This lightweight shim
 * wraps the vault/stream API with ErlNifResourceType objects whose
 * destructors call pii_vault_free / pii_stream_free, so native resources are
 * released exactly once when the BEAM garbage-collects the resource.
 *
 * All NIFs use the classic (env, argc, argv) ErlNifFunc signature; the vault
 * /stream resource term is passed as the first argument. Heavy calls are
 * marked ERL_NIF_DIRTY_JOB_CPU_BOUND so scanner DFA compilation and crypto
 * work do not stall the normal schedulers.
 */
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <erl_nif.h>
#include "pii_shield.h"

/* -------------------------------------------------------------------------- */
/* Resource types: hold the opaque handle, free it in the destructor.          */
/* -------------------------------------------------------------------------- */

static ErlNifResourceType *vault_res_type;
static ErlNifResourceType *stream_res_type;

typedef struct {
    PiiVaultHandle *handle;
} VaultResource;

typedef struct {
    PiiStreamHandle *handle;
} StreamResource;

static void vault_resource_dtor(ErlNifEnv *env, void *obj) {
    (void)env;
    VaultResource *res = (VaultResource *)obj;
    if (res != NULL && res->handle != NULL) {
        pii_vault_free(res->handle);
        res->handle = NULL;
    }
}

static void stream_resource_dtor(ErlNifEnv *env, void *obj) {
    (void)env;
    StreamResource *res = (StreamResource *)obj;
    if (res != NULL && res->handle != NULL) {
        pii_stream_free(res->handle);
        res->handle = NULL;
    }
}

/* -------------------------------------------------------------------------- */
/* Atoms & helpers                                                             */
/* -------------------------------------------------------------------------- */

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_invalid_input;
static ERL_NIF_TERM atom_exfiltration_blocked;
static ERL_NIF_TERM atom_token;
static ERL_NIF_TERM atom_undefined;
static ERL_NIF_TERM atom_trusted;
static ERL_NIF_TERM atom_untrusted;

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)priv;
    (void)info;

    ErlNifResourceTypeInit vault_init = {.dtor = vault_resource_dtor};
    ErlNifResourceTypeInit stream_init = {.dtor = stream_resource_dtor};

    vault_res_type = enif_init_resource_type(
        env, "PiiVault", &vault_init, ERL_NIF_RT_CREATE, NULL);
    stream_res_type = enif_init_resource_type(
        env, "PiiStream", &stream_init, ERL_NIF_RT_CREATE, NULL);
    if (vault_res_type == NULL || stream_res_type == NULL) {
        return 1;
    }

    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_invalid_input = enif_make_atom(env, "invalid_input");
    atom_exfiltration_blocked = enif_make_atom(env, "exfiltration_blocked");
    atom_token = enif_make_atom(env, "token");
    atom_undefined = enif_make_atom(env, "undefined");
    atom_trusted = enif_make_atom(env, "trusted");
    atom_untrusted = enif_make_atom(env, "untrusted");
    return 0;
}

static void unload(ErlNifEnv *env, void *priv) {
    (void)env;
    (void)priv;
}

/* Copies a returned *char into an Erlang binary, then frees the Rust heap. */
static ERL_NIF_TERM owned_string_term(ErlNifEnv *env, char *str) {
    if (str == NULL) {
        return atom_invalid_input;
    }
    ERL_NIF_TERM out;
    size_t len = strlen(str);
    unsigned char *data = enif_make_new_binary(env, len, &out);
    if (data != NULL && len > 0) {
        memcpy(data, str, len);
    }
    pii_string_free(str);
    return out;
}

/* Copies a string argument (Elixir String/binary or atom) into `buf`
 * (empty buffer on :undefined). */
static int get_cstring(ErlNifEnv *env, ERL_NIF_TERM term, char *buf, size_t buf_len) {
    if (enif_is_identical(term, atom_undefined)) {
        buf[0] = '\0';
        return 1;
    }
    ErlNifBinary bin;
    if (!enif_inspect_iolist_as_binary(env, term, &bin) || bin.size >= buf_len) {
        return 0;
    }
    if (bin.size == 0) {
        buf[0] = '\0';
        return 1;
    }
    memcpy(buf, bin.data, bin.size);
    buf[bin.size] = '\0';
    return 1;
}

/* Wraps a newly created handle into a resource term, leaving ownership with
 * the BEAM garbage collector (dtor frees the handle). */
static ERL_NIF_TERM vault_resource_term(ErlNifEnv *env, PiiVaultHandle *handle) {
    VaultResource *res = enif_alloc_resource(vault_res_type, sizeof(VaultResource));
    if (res == NULL) {
        pii_vault_free(handle);
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    res->handle = handle;
    ERL_NIF_TERM term = enif_make_resource(env, res);
    enif_release_resource(res);
    return enif_make_tuple2(env, atom_ok, term);
}

static ERL_NIF_TERM stream_resource_term(ErlNifEnv *env, PiiStreamHandle *handle) {
    StreamResource *res = enif_alloc_resource(stream_res_type, sizeof(StreamResource));
    if (res == NULL) {
        pii_stream_free(handle);
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    res->handle = handle;
    ERL_NIF_TERM term = enif_make_resource(env, res);
    enif_release_resource(res);
    return enif_make_tuple2(env, atom_ok, term);
}

static int get_vault(ErlNifEnv *env, ERL_NIF_TERM term, PiiVaultHandle **out) {
    VaultResource *res = NULL;
    if (!enif_get_resource(env, term, vault_res_type, (void **)&res) || res == NULL ||
        res->handle == NULL) {
        return 0;
    }
    *out = res->handle;
    return 1;
}

static int get_stream(ErlNifEnv *env, ERL_NIF_TERM term, PiiStreamHandle **out) {
    StreamResource *res = NULL;
    if (!enif_get_resource(env, term, stream_res_type, (void **)&res) || res == NULL ||
        res->handle == NULL) {
        return 0;
    }
    *out = res->handle;
    return 1;
}

/* Copies an iolist/binary argument into a NUL-terminated heap buffer. */
static int get_binary_cstring(ErlNifEnv *env, ERL_NIF_TERM term, char **out, size_t max) {
    ErlNifBinary bin;
    if (!enif_inspect_iolist_as_binary(env, term, &bin) || bin.size >= max) {
        return 0;
    }
    char *buf = enif_alloc(bin.size + 1);
    if (buf == NULL) {
        return 0;
    }
    if (bin.size > 0) {
        memcpy(buf, bin.data, bin.size);
    }
    buf[bin.size] = '\0';
    *out = buf;
    return 1;
}

static int get_trust(ERL_NIF_TERM term) {
    if (enif_is_identical(term, atom_trusted)) {
        return 1;
    }
    if (enif_is_identical(term, atom_untrusted)) {
        return 0;
    }
    return -1;
}

/* -------------------------------------------------------------------------- */
/* Vault lifecycle                                                             */
/* -------------------------------------------------------------------------- */

static ERL_NIF_TERM vault_new_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;
    PiiVaultHandle *vault = pii_vault_new();
    if (vault == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return vault_resource_term(env, vault);
}

static ERL_NIF_TERM vault_new_with_locales_nif(ErlNifEnv *env, int argc,
                                               const ERL_NIF_TERM argv[]) {
    (void)argc;
    char locales[512];
    if (!get_cstring(env, argv[0], locales, sizeof(locales))) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    PiiVaultHandle *vault =
        pii_vault_new_with_locales(locales[0] != '\0' ? locales : NULL);
    if (vault == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return vault_resource_term(env, vault);
}

static ERL_NIF_TERM vault_new_with_key_nif(ErlNifEnv *env, int argc,
                                           const ERL_NIF_TERM argv[]) {
    (void)argc;
    char locales[512];
    if (!get_cstring(env, argv[0], locales, sizeof(locales))) {
        return enif_make_badarg(env);
    }
    ErlNifBinary key_bin;
    if (!enif_inspect_binary(env, argv[1], &key_bin) || key_bin.size != 32) {
        return enif_make_badarg(env);
    }
    unsigned char key[32];
    memcpy(key, key_bin.data, 32);

    PiiVaultHandle *vault = pii_vault_new_with_locales_and_key(
        locales[0] != '\0' ? locales : NULL, key, 32);
    if (vault == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return vault_resource_term(env, vault);
}

static ERL_NIF_TERM vault_with_custom_toml_nif(ErlNifEnv *env, int argc,
                                               const ERL_NIF_TERM argv[]) {
    (void)argc;
    char locales[512];
    if (!get_cstring(env, argv[0], locales, sizeof(locales))) {
        return enif_make_badarg(env);
    }
    char *toml = NULL;
    if (!get_binary_cstring(env, argv[1], &toml, 65536)) {
        return enif_make_badarg(env);
    }
    const unsigned char *key_ptr = NULL;
    size_t key_len = 0;
    ErlNifBinary key_bin;
    if (!enif_is_identical(argv[2], atom_undefined)) {
        if (!enif_inspect_binary(env, argv[2], &key_bin)) {
            enif_free(toml);
            return enif_make_badarg(env);
        }
        key_ptr = key_bin.data;
        key_len = key_bin.size;
    }

    PiiVaultHandle *vault = pii_vault_with_custom_toml(
        locales[0] != '\0' ? locales : NULL, toml, key_ptr, key_len);
    enif_free(toml);
    if (vault == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return vault_resource_term(env, vault);
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

static ERL_NIF_TERM vault_set_token_format_nif(ErlNifEnv *env, int argc,
                                               const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    ErlNifSInt64 fmt = 0;
    if (!get_vault(env, argv[0], &vault) || !enif_get_int64(env, argv[1], &fmt)) {
        return enif_make_badarg(env);
    }
    pii_vault_set_token_format(vault, (unsigned char)fmt);
    return atom_ok;
}

static ERL_NIF_TERM vault_set_stateless_mode_nif(ErlNifEnv *env, int argc,
                                                 const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    ErlNifSInt64 enabled = 0;
    if (!get_vault(env, argv[0], &vault) || !enif_get_int64(env, argv[1], &enabled)) {
        return enif_make_badarg(env);
    }
    pii_vault_set_stateless_mode(vault, enabled != 0);
    return atom_ok;
}

/* -------------------------------------------------------------------------- */
/* Redaction / rehydration                                                     */
/* -------------------------------------------------------------------------- */

static ERL_NIF_TERM vault_redact_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    char *text = NULL;
    if (!get_vault(env, argv[0], &vault) || !get_binary_cstring(env, argv[1], &text, 1048576)) {
        return enif_make_badarg(env);
    }
    char *result = pii_vault_redact(vault, text);
    enif_free(text);
    return enif_make_tuple2(env, atom_ok, owned_string_term(env, result));
}

static ERL_NIF_TERM vault_redact_json_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    char *payload = NULL;
    if (!get_vault(env, argv[0], &vault) || !get_binary_cstring(env, argv[1], &payload, 1048576)) {
        return enif_make_badarg(env);
    }
    char *result = pii_vault_redact_json(vault, payload);
    enif_free(payload);
    return enif_make_tuple2(env, atom_ok, owned_string_term(env, result));
}

static ERL_NIF_TERM vault_rehydrate_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    char *text = NULL;
    if (!get_vault(env, argv[0], &vault) || !get_binary_cstring(env, argv[1], &text, 1048576)) {
        return enif_make_badarg(env);
    }
    char *result = pii_vault_rehydrate(vault, text);
    enif_free(text);
    return enif_make_tuple2(env, atom_ok, owned_string_term(env, result));
}

static ERL_NIF_TERM vault_rehydrate_for_tool_nif(ErlNifEnv *env, int argc,
                                                 const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    char *payload = NULL;
    if (!get_vault(env, argv[0], &vault) || !get_binary_cstring(env, argv[1], &payload, 1048576)) {
        return enif_make_badarg(env);
    }
    int trust = get_trust(argv[2]);
    if (trust < 0) {
        enif_free(payload);
        return enif_make_badarg(env);
    }
    char *err_out = NULL;
    char *result = pii_vault_rehydrate_for_tool_ex(vault, payload, trust != 0, &err_out);
    enif_free(payload);
    if (result == NULL) {
        if (err_out != NULL) {
            ERL_NIF_TERM token = owned_string_term(env, err_out);
            return enif_make_tuple2(
                env, atom_error,
                enif_make_tuple2(env, atom_exfiltration_blocked,
                                 enif_make_tuple2(env, atom_token, token)));
        }
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return enif_make_tuple2(env, atom_ok, owned_string_term(env, result));
}

/* -------------------------------------------------------------------------- */
/* Streaming                                                                   */
/* -------------------------------------------------------------------------- */

static ERL_NIF_TERM stream_new_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;
    PiiStreamHandle *stream = pii_stream_new();
    if (stream == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return stream_resource_term(env, stream);
}

static ERL_NIF_TERM stream_push_chunk_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiStreamHandle *stream = NULL;
    PiiVaultHandle *vault = NULL;
    char *text = NULL;
    if (!get_stream(env, argv[0], &stream) || !get_vault(env, argv[1], &vault) ||
        !get_binary_cstring(env, argv[2], &text, 1048576)) {
        return enif_make_badarg(env);
    }
    char *result = pii_stream_push_chunk(stream, vault, text);
    enif_free(text);
    return enif_make_tuple2(env, atom_ok, owned_string_term(env, result));
}

static ERL_NIF_TERM stream_flush_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiStreamHandle *stream = NULL;
    PiiVaultHandle *vault = NULL;
    if (!get_stream(env, argv[0], &stream) || !get_vault(env, argv[1], &vault)) {
        return enif_make_badarg(env);
    }
    char *result = pii_stream_flush(stream, vault);
    return enif_make_tuple2(env, atom_ok, owned_string_term(env, result));
}

/* -------------------------------------------------------------------------- */
/* NIF table                                                                   */
/* -------------------------------------------------------------------------- */

static ErlNifFunc nif_funcs[] = {
    {"vault_new", 0, vault_new_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_new_with_locales", 1, vault_new_with_locales_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_new_with_key", 2, vault_new_with_key_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_with_custom_toml", 3, vault_with_custom_toml_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_set_token_format", 2, vault_set_token_format_nif, 0},
    {"vault_set_stateless_mode", 2, vault_set_stateless_mode_nif, 0},
    {"vault_redact", 2, vault_redact_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_redact_json", 2, vault_redact_json_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_rehydrate", 2, vault_rehydrate_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_rehydrate_for_tool", 3, vault_rehydrate_for_tool_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_new", 0, stream_new_nif, 0},
    {"stream_push_chunk", 3, stream_push_chunk_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_flush", 2, stream_flush_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

/* ERL_NIF_INIT() cannot handle Elixir module names (the macro stringifies the
 * module into a single C identifier, but the entry's `name` field must be
 * exactly "Elixir.PiiShield.Nif"). Define the ErlNifEntry manually instead;
 * BEAM looks up the `nif_init` symbol when loading a dynamic NIF library. */

ERL_NAPI_EXPORT int nif_init(void);

int nif_init(void) {
    static ErlNifEntry entry = {
        ERL_NIF_MAJOR_VERSION,
        ERL_NIF_MINOR_VERSION,
        "Elixir.PiiShield.Nif",
        sizeof(nif_funcs) / sizeof(*nif_funcs),
        nif_funcs,
        &load, NULL /* reload is gone since OTP 20 */, NULL,
        &unload,
        ERL_NIF_VM_VARIANT,
        1,
        sizeof(ErlNifResourceTypeInit),
        ERL_NIF_MIN_ERTS_VERSION,
    };
    return (int)(long)&entry;
}
