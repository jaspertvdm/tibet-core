/**
 * TIBET C Bindings Test
 *
 * Compile: gcc -o test test.c -L../target/release -ltibet_core -Iinclude
 * Run: LD_LIBRARY_PATH=../target/release ./test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/tibet.h"

int main() {
    printf("=== TIBET C Bindings Test ===\n\n");

    // Check version
    printf("Version: %s\n\n", tibet_version());

    // Create engine
    printf("Creating TIBET engine...\n");
    tibet_engine_t* engine = tibet_engine_new();
    if (!engine) {
        printf("ERROR: Failed to create engine\n");
        return 1;
    }

    // Get public key
    char* pubkey = tibet_get_public_key(engine);
    printf("Public key: %.32s...\n\n", pubkey);

    // Create a token
    printf("Creating token...\n");
    char* token = tibet_create_token(
        engine,
        "action",                    // type
        "Embedded device reading",   // ERIN - what
        "[\"sensor_v1\"]",          // ERAAN - dependencies
        "{\"device\":\"6G-chip\"}",  // EROMHEEN - context
        "Periodic sensor reading",   // ERACHTER - why
        "did:jis:device:001",        // actor
        NULL                         // no parent
    );

    if (!token) {
        printf("ERROR: Failed to create token\n");
        tibet_free_string(pubkey);
        tibet_engine_free(engine);
        return 1;
    }

    printf("Token (first 200 chars):\n%.200s...\n\n", token);

    // Verify token
    printf("Verifying token...\n");
    bool valid = tibet_verify(engine, token);
    printf("Valid: %s\n\n", valid ? "YES" : "NO");

    // Sign a message
    printf("Signing message...\n");
    char* signature = tibet_sign_string(engine, "Hello from 6G!");
    printf("Signature: %.32s...\n\n", signature);

    // Cleanup
    tibet_free_string(signature);
    tibet_free_string(token);
    tibet_free_string(pubkey);
    tibet_engine_free(engine);

    printf("=== ALL TESTS PASSED ===\n");
    return 0;
}
