#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "pii_shield.h"

int main(void) {
    printf("[C ABI E2E] Initializing PiiVaultHandle from C...\n");

    // 1. Create vault using locales
    struct PiiVaultHandle *vault = pii_vault_new_with_locales("global,id");
    assert(vault != NULL);

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

    // 5. Free strings and vault
    pii_string_free(redacted);
    pii_string_free(rehydrated);
    pii_string_free(tool_rehydrated);
    pii_vault_free(vault);

    printf("[C ABI E2E] All native C tests passed cleanly with 0 errors!\n");
    return 0;
}
