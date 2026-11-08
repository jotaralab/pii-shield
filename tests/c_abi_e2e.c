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

    // 4. Test tool rehydration
    const char *tool_call = "{\"nik\":\"<ID_NIK_1>\"}";
    char *tool_rehydrated = pii_vault_rehydrate_for_tool(vault, tool_call, true);
    assert(tool_rehydrated != NULL);

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
    unsigned char key32[32];
    memset(key32, 7, sizeof(key32));
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
    pii_string_free(trusted);

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
    pii_string_free(acc_redacted);
    pii_string_free(acc_rehydrated);
    pii_string_free(c1);
    pii_string_free(c2);
    pii_string_free(sflush);
    free(left);
    free(joined);
    pii_stream_free(stream);
    pii_vault_free(vault);
    pii_vault_free(cvault);

    printf("[C ABI E2E] All native C tests passed cleanly with 0 errors!\n");
    return 0;
}
