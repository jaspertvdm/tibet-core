/**
 * TIBET: Transaction/Interaction-Based Evidence Trail
 * C Bindings for embedded systems, 6G, and hardware integration
 *
 * Copyright (c) 2026 Humotica
 * License: MIT OR Apache-2.0
 *
 * Example:
 *   #include <tibet.h>
 *
 *   tibet_engine_t* engine = tibet_engine_new();
 *   const char* token = tibet_create_token(engine, "action", "content",
 *                                          "[]", "{}", "intent", "actor", NULL);
 *   bool valid = tibet_verify(engine, token);
 *   tibet_free_string(token);
 *   tibet_engine_free(engine);
 */

#ifndef TIBET_H
#define TIBET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle to TIBET engine */
typedef struct tibet_engine tibet_engine_t;

/* ============================================
 * Engine Lifecycle
 * ============================================ */

/**
 * Create a new TIBET engine with fresh Ed25519 keypair
 * Returns: New engine handle, or NULL on failure
 * Caller must free with tibet_engine_free()
 */
tibet_engine_t* tibet_engine_new(void);

/**
 * Create engine from existing secret key
 * @param secret_hex: 64-character hex string (32 bytes)
 * Returns: New engine handle, or NULL on invalid key
 */
tibet_engine_t* tibet_engine_from_secret(const char* secret_hex);

/**
 * Free engine and associated resources
 */
void tibet_engine_free(tibet_engine_t* engine);

/* ============================================
 * Key Management
 * ============================================ */

/**
 * Get public key as hex string
 * Returns: 64-character hex string
 * Caller must free with tibet_free_string()
 */
char* tibet_get_public_key(const tibet_engine_t* engine);

/* ============================================
 * Token Operations
 * ============================================ */

/**
 * Create a new TIBET token
 * @param engine: TIBET engine handle
 * @param token_type: Token type (e.g., "action", "decision", "message")
 * @param erin: WHAT - Content of the action
 * @param eraan_json: WITH - JSON array of dependencies ["dep1", "dep2"]
 * @param eromheen_json: WHERE - JSON object of context {"key": "value"}
 * @param erachter: WHY - Intent behind the action
 * @param actor: WHO - Actor identifier (DID recommended)
 * @param parent_id: Parent token ID for chaining (NULL for genesis)
 * Returns: JSON string of token, or NULL on failure
 * Caller must free with tibet_free_string()
 */
char* tibet_create_token(
    tibet_engine_t* engine,
    const char* token_type,
    const char* erin,
    const char* eraan_json,
    const char* eromheen_json,
    const char* erachter,
    const char* actor,
    const char* parent_id
);

/**
 * Verify a token's signature
 * @param engine: TIBET engine handle
 * @param token_json: JSON string of token
 * Returns: true if valid, false otherwise
 */
bool tibet_verify(const tibet_engine_t* engine, const char* token_json);

/**
 * Verify token with external public key
 * @param token_json: JSON string of token
 * @param public_key_hex: 64-character hex public key
 * Returns: true if valid, false otherwise
 */
bool tibet_verify_with_key(const char* token_json, const char* public_key_hex);

/* ============================================
 * Signing (standalone)
 * ============================================ */

/**
 * Sign arbitrary data
 * @param engine: TIBET engine handle
 * @param data: Data to sign
 * @param data_len: Length of data
 * Returns: Hex-encoded signature (128 chars)
 * Caller must free with tibet_free_string()
 */
char* tibet_sign(const tibet_engine_t* engine, const uint8_t* data, size_t data_len);

/**
 * Sign a string message
 * @param engine: TIBET engine handle
 * @param message: Null-terminated string
 * Returns: Hex-encoded signature
 * Caller must free with tibet_free_string()
 */
char* tibet_sign_string(const tibet_engine_t* engine, const char* message);

/* ============================================
 * Memory Management
 * ============================================ */

/**
 * Free a string returned by TIBET functions
 */
void tibet_free_string(char* s);

/* ============================================
 * Version Info
 * ============================================ */

/**
 * Get TIBET library version
 * Returns: Version string (e.g., "0.1.1")
 * Do NOT free this string
 */
const char* tibet_version(void);

#ifdef __cplusplus
}
#endif

#endif /* TIBET_H */
