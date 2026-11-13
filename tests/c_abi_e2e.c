#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "pii_shield.h"

static const char *CUSTOM_TOML =
    "locale = \"custom\"\n"
    "name = \"Custom\"\n\n"
    "[[rules]]\n"
    "id = \"CUSTOM_ACC\"\n"
    "tag_prefix = \"CUSTOM_ACC\"\n"
    "regex = '\\bACC-[0-9]{6}\\b'\n"
    "validator = \"none\"\n";

int main(void) {
    printf("[C ABI E2E] Initializing PiiVaultHandle from C...\n");

    // 1. Create vault using locales
    struct PiiVaultHandle *vault = pii_vault_new_with_locales("global,id");
    assert(vault != NULL);

    // An unknown locale must fail closed (NULL), never fall back to an
    // empty 0-rule catalog.
    assert(pii_vault_new_with_locales("global_typo") == NULL);

    // Set token format to CompactHash (1)
    pii_vault_set_token_format(vault, 1);

    // 2. Redact text
    const char *prompt = "User NIK 3573012203950001 dan email budi@contoh.id";
    char *redacted = pii_vault_redact(vault, prompt);
    assert(redacted != NULL);
    printf("[C ABI E2E] Redacted string: %s\n", redacted);

    assert(strstr(redacted, "<ID_NIK_") != NULL);
    assert(strstr(redacted, "<EMAIL_") != NULL);
    assert(strstr(redacted, "3573012203950001") == NULL);

    // 3. Rehydrate
    char *rehydrated = pii_vault_rehydrate(vault, redacted);
    assert(rehydrated != NULL);
    printf("[C ABI E2E] Rehydrated string: %s\n", rehydrated);
    assert(strcmp(rehydrated, prompt) == 0);

    // 4. Test tool rehydration: tokens inside the *redacted* input for an
    //    untrusted tool come back redacted; a trusted tool sees plaintext.
    //    Use the actual token emitted by `pii_vault_redact` rather than a
    //    hardcoded token id.
    char token[128];
    {
        const char *start = strstr(redacted, "<ID_NIK_");
        assert(start != NULL);
        const char *end = strchr(start, '>');
        assert(end != NULL);
        size_t tlen = (size_t)(end - start + 1);
        assert(tlen < sizeof(token));
        memcpy(token, start, tlen);
        token[tlen] = '\0';
    }
    char tool_call[256];
    snprintf(tool_call, sizeof(tool_call), "{\"nik\":\"%s\"}", token);
    char *tool_rehydrated = pii_vault_rehydrate_for_tool(vault, tool_call, true);
    assert(tool_rehydrated != NULL);
    assert(strstr(tool_rehydrated, "3573012203950001") != NULL);

    // 4b. Custom TOML keyed with the explicit shared key (keyed path) and
    //     cross-vault rehydration. Stateless sealed tokens carry their
    //     ciphertext, so a fresh vault with the same key rehydrates them.
    unsigned char key32[32];
    memset(key32, 7, sizeof(key32));
    struct PiiVaultHandle *kvault = pii_vault_with_custom_toml("global", CUSTOM_TOML, key32, sizeof(key32));
    assert(kvault != NULL);
    struct PiiVaultHandle *kvault2 = pii_vault_with_custom_toml("global", CUSTOM_TOML, key32, sizeof(key32));
    assert(kvault2 != NULL);
    pii_vault_set_token_format(kvault, 2);
    pii_vault_set_token_format(kvault2, 2);
    char *kred = pii_vault_redact(kvault, "Account ACC-999999 opened");
    assert(kred != NULL && strstr(kred, "<PII:CUSTOM_ACC:") != NULL);
    char *krehydrated = pii_vault_rehydrate(kvault2, kred);
    assert(krehydrated != NULL);
    assert(strcmp(krehydrated, "Account ACC-999999 opened") == 0);
    pii_string_free(kred);
    pii_string_free(krehydrated);

    // 5. Custom TOML constructor (CSPRNG key path)
    struct PiiVaultHandle *cvault = pii_vault_with_custom_toml("global", CUSTOM_TOML, NULL, 0);
    assert(cvault != NULL);
    char *acc_redacted = pii_vault_redact(cvault, "Account ACC-123456 opened");
    assert(acc_redacted != NULL);
    printf("[C ABI E2E] Custom TOML redacted: %s\n", acc_redacted);
    assert(strstr(acc_redacted, "<CUSTOM_ACC_") != NULL);
    char *acc_rehydrated = pii_vault_rehydrate(cvault, acc_redacted);
    assert(acc_rehydrated != NULL);
    assert(strcmp(acc_rehydrated, "Account ACC-123456 opened") == 0);

    // Invalid key length must fail closed.
    const unsigned char short_key[16] = {0};
    assert(pii_vault_with_custom_toml("global", CUSTOM_TOML, short_key, sizeof(short_key)) == NULL);
    assert(pii_vault_with_custom_toml("global", CUSTOM_TOML, NULL, 32) == NULL);

    // 6. rehydrate_for_tool_ex reports the blocked token.
    char *err_out = NULL;
    char *blocked_ok = pii_vault_rehydrate_for_tool_ex(vault, redacted, false, &err_out);
    assert(blocked_ok == NULL);
    assert(err_out != NULL);
    printf("[C ABI E2E] Blocked token via _ex: %s\n", err_out);
    /* The vault may report whichever offending token it finds first
     * (NIK or email); assert the format instead of a fixed entity. */
    assert(err_out[0] == '<');
    assert(strchr(err_out, '>') != NULL);
    pii_string_free(err_out);

    // Trusted call still rehydrates and must not touch err_out.
    err_out = (char *)0x1; // poison sentinel
    char *trusted = pii_vault_rehydrate_for_tool_ex(vault, redacted, true, &err_out);
    assert(trusted != NULL);
    assert(err_out == NULL);
    assert(strcmp(trusted, prompt) == 0);
    pii_string_free(trusted);

    // 6b. Two-phase dirty sync from C: seal without clearing, then clear by
    //     the tokens contained in the sealed map.
    const char *aad = "session:c_abi_e2e";
    char *sealed = pii_vault_seal_dirty_sealed_entries_json(vault, aad);
    assert(sealed != NULL && strstr(sealed, "PIIE1:") != NULL);
    // Extract every key (token) of the sealed JSON map into a tokens array.
    char tokens_json[1024];
    tokens_json[0] = '[';
    size_t pos = 1;
    const char *p = sealed;
    while ((p = strchr(p, '"')) != NULL) {
        const char *q1 = p;              // opening quote
        const char *q2 = strchr(q1 + 1, '"');
        assert(q2 != NULL);
        // Only keys precede a ':' within the same pair.
        if (q2[1] == ':') {
            if (pos > 1) {
                tokens_json[pos++] = ',';
            }
            memcpy(tokens_json + pos, q1, (size_t)(q2 - q1 + 1));
            pos += (size_t)(q2 - q1 + 1);
        }
        p = q2 + 1;
    }
    tokens_json[pos++] = ']';
    tokens_json[pos] = '\0';
    assert(pii_vault_clear_dirty_tokens(vault, tokens_json));
    char *sealed2 = pii_vault_seal_dirty_sealed_entries_json(vault, aad);
    assert(sealed2 != NULL && strcmp(sealed2, "{}") == 0);
    pii_string_free(sealed);
    pii_string_free(sealed2);

    // 6c-1. export/import sealed state round-trip into a fresh vault sharing
    //     the same 32-byte key (state envelopes are keyed, so a vault with a
    //     different key must fail closed).
    struct PiiVaultHandle *svault_a = pii_vault_with_custom_toml("global", CUSTOM_TOML, key32, sizeof(key32));
    assert(svault_a != NULL);
    struct PiiVaultHandle *svault_b = pii_vault_with_custom_toml("global", CUSTOM_TOML, key32, sizeof(key32));
    assert(svault_b != NULL);
    pii_vault_set_token_format(svault_a, 1);
    pii_vault_set_token_format(svault_b, 1);
    char *kred2 = pii_vault_redact(svault_a, "Account ACC-123456 opened");
    assert(kred2 != NULL && strstr(kred2, "<CUSTOM_ACC_") != NULL);
    const char *aad2 = "session:c_abi_state";
    char *state_blob = pii_vault_export_sealed_state(svault_a, aad2);
    assert(state_blob != NULL && strstr(state_blob, "PIIS1:") != NULL);
    // Wrong key must fail closed.
    unsigned char other_key[32];
    memset(other_key, 9, sizeof(other_key));
    struct PiiVaultHandle *svault_c = pii_vault_with_custom_toml("global", CUSTOM_TOML, other_key, sizeof(other_key));
    assert(svault_c != NULL);
    assert(!pii_vault_import_sealed_state(svault_c, state_blob, aad2));
    // Same key imports and rehydrates.
    assert(pii_vault_import_sealed_state(svault_b, state_blob, aad2));
    char *srehydrated = pii_vault_rehydrate(svault_b, kred2);
    assert(srehydrated != NULL);
    assert(strcmp(srehydrated, "Account ACC-123456 opened") == 0);
    pii_string_free(state_blob);

    // 6c-2. redact_json redacts PII inside JSON payloads.
    char *json_redacted = pii_vault_redact_json(
        vault, "{\"email\":\"budi@contoh.id\",\"note\":\"NIK 3573012203950001\"}");
    assert(json_redacted != NULL);
    assert(strstr(json_redacted, "budi@contoh.id") == NULL);
    assert(strstr(json_redacted, "3573012203950001") == NULL);
    assert(strstr(json_redacted, "<EMAIL_") != NULL);

    // 6c. is_stateless_mode toggles.
    pii_vault_set_stateless_mode(vault, true);
    assert(pii_vault_is_stateless_mode(vault));
    pii_vault_set_stateless_mode(vault, false);
    assert(!pii_vault_is_stateless_mode(vault));
    assert(!pii_vault_is_stateless_mode(NULL));

    // Legacy entry point still returns plain NULL on block (ABI compat).
    assert(pii_vault_rehydrate_for_tool(vault, redacted, false) == NULL);

    // 7. Streaming rehydrator: tokens split across chunks rehydrate.
    struct PiiStreamHandle *stream = pii_stream_new();
    assert(stream != NULL);
    size_t half = strlen(redacted) / 2;
    char *left = malloc(half + 1);
    assert(left != NULL);
    memcpy(left, redacted, half);
    left[half] = '\0';
    char *c1 = pii_stream_push_chunk(stream, vault, left);
    char *c2 = pii_stream_push_chunk(stream, vault, redacted + half);
    char *sflush = pii_stream_flush(stream, vault);
    assert(c1 != NULL && c2 != NULL && sflush != NULL);
    size_t joined_len = strlen(c1) + strlen(c2) + strlen(sflush) + 1;
    char *joined = malloc(joined_len);
    assert(joined != NULL);
    joined[0] = '\0';
    strcat(joined, c1);
    strcat(joined, c2);
    strcat(joined, sflush);
    printf("[C ABI E2E] Streamed: %s\n", joined);
    assert(strcmp(joined, prompt) == 0);

    // 8. Free strings and vaults
    pii_string_free(redacted);
    pii_string_free(rehydrated);
    pii_string_free(tool_rehydrated);
    pii_string_free(json_redacted);
    pii_string_free(kred2);
    pii_string_free(srehydrated);
    pii_string_free(acc_redacted);
    pii_string_free(acc_rehydrated);
    pii_string_free(c1);
    pii_string_free(c2);
    pii_string_free(sflush);
    free(left);
    free(joined);
    pii_stream_free(stream);
    pii_vault_free(vault);
    pii_vault_free(svault_a);
    pii_vault_free(svault_b);
    pii_vault_free(svault_c);
    pii_vault_free(cvault);
    pii_vault_free(kvault);
    pii_vault_free(kvault2);

    printf("[C ABI E2E] All native C tests passed cleanly with 0 errors!\n");
    return 0;
}
