/*
 * Erlang NIF shim wrapping the pii-ffi C-ABI (pii_shield.h).
 *
 * The BEAM cannot load a bare C-ABI .so: it needs erl_nif.h-style resource
 * objects. This shim wraps the vault/stream API with ErlNifResourceType
 * objects whose destructors call pii_vault_free / pii_stream_free, so native
 * resources are released exactly once when the BEAM garbage-collects the
 * resource.
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

    ErlNifResourceTypeInit vault_init;
    memset(&vault_init, 0, sizeof(vault_init));
    vault_init.dtor = vault_resource_dtor;
    ErlNifResourceTypeInit stream_init;
    memset(&stream_init, 0, sizeof(stream_init));
    stream_init.dtor = stream_resource_dtor;

    vault_res_type = enif_init_resource_type(
        env, "PiiVault", &vault_init, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    stream_res_type = enif_init_resource_type(
        env, "PiiStream", &stream_init, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
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

/* A code upgrade simply re-runs load(); the resource types survive via
 * ERL_NIF_RT_TAKEOVER and the module state (atoms) is re-initialized. */
static int upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data,
                   ERL_NIF_TERM load_info) {
    (void)old_priv_data;
    return load(env, priv_data, load_info);
}

static void unload(ErlNifEnv *env, void *priv) {
    (void)env;
    (void)priv;
}

/* Converts a returned *mut c_char into `{:ok, binary}` or
 * `{:error, :invalid_input}`. NULL results (native call failure) are never
 * silently wrapped as an empty binary; the Rust heap buffer is always freed. */
static ERL_NIF_TERM owned_string_result(ErlNifEnv *env, char *str) {
    if (str == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    ERL_NIF_TERM out;
    size_t len = strlen(str);
    unsigned char *data = enif_make_new_binary(env, len, &out);
    if (data == NULL) {
        pii_string_free(str);
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    if (len > 0) {
        memcpy(data, str, len);
    }
    pii_string_free(str);
    return enif_make_tuple2(env, atom_ok, out);
}

/* Copies a "string" argument (Elixir String/binary) into `buf`. The atom
 * :undefined yields an empty buffer (used where the C side accepts NULL /
 * defaults). Fails on strings that are too long or contain interior NUL
 * bytes (which would silently truncate at the C boundary). Returns:
 * 1 = ok, 0 = inspect/size failure, -1 = interior NUL. */
static int get_cstring(ErlNifEnv *env, ERL_NIF_TERM term, char *buf, size_t buf_len) {
    if (enif_is_identical(term, atom_undefined)) {
        buf[0] = '\0';
        return 1;
    }
    ErlNifBinary bin;
    if (!enif_inspect_iolist_as_binary(env, term, &bin) || bin.size >= buf_len) {
        return 0;
    }
    if (bin.size > 0 && memchr(bin.data, '\0', bin.size) != NULL) {
        return -1;
    }
    memcpy(buf, bin.data, bin.size);
    buf[bin.size] = '\0';
    return 1;
}

/* Copies an iolist/binary argument into a NUL-terminated heap buffer of any
 * size (the earlier 1 MiB cap rejected legitimate large payloads; the caller
 * keeps ownership via enif_free). Rejects interior NUL bytes.
 * Returns: 1 = ok, 0 = inspect failure, -1 = interior NUL,
 * -2 = allocation failure. */
static int get_binary_cstring(ErlNifEnv *env, ERL_NIF_TERM term, char **out) {
    ErlNifBinary bin;
    if (!enif_inspect_iolist_as_binary(env, term, &bin)) {
        return 0;
    }
    if (bin.size > 0 && memchr(bin.data, '\0', bin.size) != NULL) {
        return -1;
    }
    char *buf = enif_alloc(bin.size + 1);
    if (buf == NULL) {
        return -2;
    }
    if (bin.size > 0) {
        memcpy(buf, bin.data, bin.size);
    }
    buf[bin.size] = '\0';
    *out = buf;
    return 1;
}

/* Copies a required (non-:undefined) string, rejecting empty and NUL
 * (used for locale CSVs, where "" must fail closed instead of selecting the
 * default "global,id" set). Returns: 1 = ok, 0 = failure/badarg. */
static int get_required_cstring(ErlNifEnv *env, ERL_NIF_TERM term, char *buf, size_t buf_len) {
    if (enif_is_identical(term, atom_undefined)) {
        return 0;
    }
    int rc = get_cstring(env, term, buf, buf_len);
    if (rc != 1 || buf[0] == '\0') {
        return 0;
    }
    return 1;
}

/* Maps a get_* helper failure to badarg. */
static ERL_NIF_TERM badarg_or_invalid(ErlNifEnv *env, int rc) {
    (void)rc;
    return enif_make_badarg(env);
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
    if (!get_required_cstring(env, argv[0], locales, sizeof(locales))) {
        return enif_make_badarg(env);
    }
    PiiVaultHandle *vault = pii_vault_new_with_locales(locales);
    if (vault == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return vault_resource_term(env, vault);
}

static ERL_NIF_TERM vault_new_with_key_nif(ErlNifEnv *env, int argc,
                                           const ERL_NIF_TERM argv[]) {
    (void)argc;
    char locales[512];
    const char *locales_ptr = NULL;
    if (!enif_is_identical(argv[0], atom_undefined)) {
        if (!get_required_cstring(env, argv[0], locales, sizeof(locales))) {
            return enif_make_badarg(env);
        }
        locales_ptr = locales;
    }
    ErlNifBinary key_bin;
    if (!enif_inspect_binary(env, argv[1], &key_bin) || key_bin.size != 32) {
        return enif_make_badarg(env);
    }
    unsigned char key[32];
    memcpy(key, key_bin.data, 32);

    PiiVaultHandle *vault = pii_vault_new_with_locales_and_key(locales_ptr, key, 32);
    memset(key, 0, sizeof(key));
    if (vault == NULL) {
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return vault_resource_term(env, vault);
}

static ERL_NIF_TERM vault_with_custom_toml_nif(ErlNifEnv *env, int argc,
                                               const ERL_NIF_TERM argv[]) {
    (void)argc;
    char locales[512];
    const char *locales_ptr = NULL;
    if (!enif_is_identical(argv[0], atom_undefined)) {
        if (!get_required_cstring(env, argv[0], locales, sizeof(locales))) {
            return enif_make_badarg(env);
        }
        locales_ptr = locales;
    }
    char *toml = NULL;
    int trc = get_binary_cstring(env, argv[1], &toml);
    if (trc != 1) {
        return badarg_or_invalid(env, trc);
    }
    const unsigned char *key_ptr = NULL;
    size_t key_len = 0;
    ErlNifBinary key_bin;
    unsigned char key_copy[32];
    if (!enif_is_identical(argv[2], atom_undefined)) {
        if (!enif_inspect_binary(env, argv[2], &key_bin) || key_bin.size != 32) {
            enif_free(toml);
            return enif_make_badarg(env);
        }
        /* Copy out of the BEAM binary (which gets reclaimed) and zeroize. */
        memcpy(key_copy, key_bin.data, 32);
        key_ptr = key_copy;
        key_len = 32;
    }

    PiiVaultHandle *vault = pii_vault_with_custom_toml(locales_ptr, toml, key_ptr, key_len);
    if (key_ptr != NULL) {
        memset(key_copy, 0, sizeof(key_copy));
    }
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

static ERL_NIF_TERM vault_is_stateless_mode_nif(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    if (!get_vault(env, argv[0], &vault)) {
        return enif_make_badarg(env);
    }
    return pii_vault_is_stateless_mode(vault) ? enif_make_atom(env, "true")
                                              : enif_make_atom(env, "false");
}

/* -------------------------------------------------------------------------- */
/* Redaction / rehydration                                                     */
/* -------------------------------------------------------------------------- */

/* Shared pattern: fetch vault + NUL-terminated payload buffer, call the C
 * function, free the buffer, return owned_string_result. */
static ERL_NIF_TERM vault_op_result(ErlNifEnv *env, const ERL_NIF_TERM argv[],
                                    char *(*op)(PiiVaultHandle *, const char *)) {
    PiiVaultHandle *vault = NULL;
    char *text = NULL;
    int rc = get_binary_cstring(env, argv[1], &text);
    if (!get_vault(env, argv[0], &vault) || rc != 1) {
        if (rc == 1) {
            enif_free(text);
        }
        return enif_make_badarg(env);
    }
    char *result = op(vault, text);
    enif_free(text);
    return owned_string_result(env, result);
}

static char *redact_op(PiiVaultHandle *v, const char *s) { return pii_vault_redact(v, s); }

static char *redact_json_op(PiiVaultHandle *v, const char *s) { return pii_vault_redact_json(v, s); }

static char *rehydrate_op(PiiVaultHandle *v, const char *s) { return pii_vault_rehydrate(v, s); }

static char *export_entries_op(PiiVaultHandle *v, const char *s) {
    return pii_vault_export_sealed_entries_json(v, s);
}

static char *drain_op(PiiVaultHandle *v, const char *s) {
    return pii_vault_drain_dirty_sealed_entries_json(v, s);
}

static char *seal_op(PiiVaultHandle *v, const char *s) {
    return pii_vault_seal_dirty_sealed_entries_json(v, s);
}

static char *export_state_op(PiiVaultHandle *v, const char *s) {
    return pii_vault_export_sealed_state(v, s);
}

static ERL_NIF_TERM vault_redact_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, redact_op);
}

static ERL_NIF_TERM vault_redact_json_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, redact_json_op);
}

static ERL_NIF_TERM vault_rehydrate_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, rehydrate_op);
}

static ERL_NIF_TERM vault_rehydrate_for_tool_nif(ErlNifEnv *env, int argc,
                                                 const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    char *payload = NULL;
    int rc = get_binary_cstring(env, argv[1], &payload);
    if (!get_vault(env, argv[0], &vault) || rc != 1) {
        if (rc == 1) {
            enif_free(payload);
        }
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
            /* Build the token binary before freeing the Rust buffer. */
            ERL_NIF_TERM token_bin;
            size_t tlen = strlen(err_out);
            unsigned char *tdata = enif_make_new_binary(env, tlen, &token_bin);
            if (tdata == NULL) {
                pii_string_free(err_out);
                return enif_raise_exception(env, enif_make_atom(env, "out_of_memory"));
            }
            memcpy(tdata, err_out, tlen);
            pii_string_free(err_out);
            return enif_make_tuple2(
                env, atom_error,
                enif_make_tuple2(env, atom_exfiltration_blocked,
                                 enif_make_tuple2(env, atom_token, token_bin)));
        }
        return enif_make_tuple2(env, atom_error, atom_invalid_input);
    }
    return owned_string_result(env, result);
}

/* -------------------------------------------------------------------------- */
/* Sealed-state / dirty-token persistence                                      */
/* -------------------------------------------------------------------------- */

static ERL_NIF_TERM vault_export_sealed_entries_json_nif(ErlNifEnv *env, int argc,
                                                         const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, export_entries_op);
}

static ERL_NIF_TERM vault_drain_dirty_sealed_entries_json_nif(ErlNifEnv *env, int argc,
                                                              const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, drain_op);
}

static ERL_NIF_TERM vault_seal_dirty_sealed_entries_json_nif(ErlNifEnv *env, int argc,
                                                             const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, seal_op);
}

static ERL_NIF_TERM vault_clear_dirty_tokens_nif(ErlNifEnv *env, int argc,
                                                 const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    char *tokens = NULL;
    int rc = get_binary_cstring(env, argv[1], &tokens);
    if (!get_vault(env, argv[0], &vault) || rc != 1) {
        if (rc == 1) {
            enif_free(tokens);
        }
        return enif_make_badarg(env);
    }
    bool ok = pii_vault_clear_dirty_tokens(vault, tokens);
    enif_free(tokens);
    return ok ? enif_make_atom(env, "true") : enif_make_atom(env, "false");
}

static ERL_NIF_TERM vault_import_sealed_entries_json_nif(ErlNifEnv *env, int argc,
                                                         const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    if (!get_vault(env, argv[0], &vault)) {
        return enif_make_badarg(env);
    }
    char *map = NULL;
    char *aad = NULL;
    int mrc = get_binary_cstring(env, argv[1], &map);
    int arc = get_binary_cstring(env, argv[2], &aad);
    if (mrc != 1 || arc != 1) {
        if (mrc == 1) enif_free(map);
        if (arc == 1) enif_free(aad);
        return enif_make_badarg(env);
    }
    bool ok = pii_vault_import_sealed_entries_json(vault, map, aad);
    enif_free(map);
    enif_free(aad);
    return ok ? enif_make_atom(env, "true") : enif_make_atom(env, "false");
}

static ERL_NIF_TERM vault_export_sealed_state_nif(ErlNifEnv *env, int argc,
                                                  const ERL_NIF_TERM argv[]) {
    (void)argc;
    return vault_op_result(env, argv, export_state_op);
}

static ERL_NIF_TERM vault_import_sealed_state_nif(ErlNifEnv *env, int argc,
                                                  const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiVaultHandle *vault = NULL;
    if (!get_vault(env, argv[0], &vault)) {
        return enif_make_badarg(env);
    }
    char *sealed = NULL;
    char *aad = NULL;
    int src = get_binary_cstring(env, argv[1], &sealed);
    int arc = get_binary_cstring(env, argv[2], &aad);
    if (src != 1 || arc != 1) {
        if (src == 1) enif_free(sealed);
        if (arc == 1) enif_free(aad);
        return enif_make_badarg(env);
    }
    bool ok = pii_vault_import_sealed_state(vault, sealed, aad);
    enif_free(sealed);
    enif_free(aad);
    return ok ? enif_make_atom(env, "true") : enif_make_atom(env, "false");
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
    int trc = get_binary_cstring(env, argv[2], &text);
    if (!get_stream(env, argv[0], &stream) || !get_vault(env, argv[1], &vault) || trc != 1) {
        if (trc == 1) {
            enif_free(text);
        }
        return enif_make_badarg(env);
    }
    char *result = pii_stream_push_chunk(stream, vault, text);
    enif_free(text);
    return owned_string_result(env, result);
}

static ERL_NIF_TERM stream_flush_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    PiiStreamHandle *stream = NULL;
    PiiVaultHandle *vault = NULL;
    if (!get_stream(env, argv[0], &stream) || !get_vault(env, argv[1], &vault)) {
        return enif_make_badarg(env);
    }
    char *result = pii_stream_flush(stream, vault);
    return owned_string_result(env, result);
}

/* -------------------------------------------------------------------------- */
/* NIF table                                                                   */
/* -------------------------------------------------------------------------- */

static ErlNifFunc nif_funcs[] = {
    {"vault_new", 0, vault_new_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_new_with_locales", 1, vault_new_with_locales_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_new_with_key", 2, vault_new_with_key_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_with_custom_toml", 3, vault_with_custom_toml_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_set_token_format", 2, vault_set_token_format_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_set_stateless_mode", 2, vault_set_stateless_mode_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_is_stateless_mode", 1, vault_is_stateless_mode_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_redact", 2, vault_redact_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_redact_json", 2, vault_redact_json_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_rehydrate", 2, vault_rehydrate_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_rehydrate_for_tool", 3, vault_rehydrate_for_tool_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_export_sealed_entries_json", 2, vault_export_sealed_entries_json_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_drain_dirty_sealed_entries_json", 2, vault_drain_dirty_sealed_entries_json_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_seal_dirty_sealed_entries_json", 2, vault_seal_dirty_sealed_entries_json_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_clear_dirty_tokens", 2, vault_clear_dirty_tokens_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_import_sealed_entries_json", 3, vault_import_sealed_entries_json_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_export_sealed_state", 2, vault_export_sealed_state_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"vault_import_sealed_state", 3, vault_import_sealed_state_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_new", 0, stream_new_nif, 0},
    {"stream_push_chunk", 3, stream_push_chunk_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_flush", 2, stream_flush_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(Elixir.PiiShield.Nif, nif_funcs, load, NULL, upgrade, unload)
