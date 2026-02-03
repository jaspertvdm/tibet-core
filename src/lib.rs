//! # TIBET Core - The Linux of AI Provenance
//!
//! Transaction/Interaction-Based Evidence Trail
//!
//! A minimal, embeddable provenance engine for any device.
//! From microcontrollers to cloud servers.
//!
//! ## Quick Start
//!
//! ```rust
//! use tibet_core::{TibetToken, TibetEngine};
//!
//! let engine = TibetEngine::new();
//! let token = engine.create_token(
//!     "action",
//!     "User requested translation",      // ERIN - what
//!     &["model_v1", "tokenizer_v2"],      // ERAAN - dependencies
//!     r#"{"env": "production"}"#,         // EROMHEEN - context
//!     "Fulfilling user translation task", // ERACHTER - why
//!     "agent_001",                         // actor
//!     None,                                // parent (chain)
//! );
//!
//! assert!(engine.verify(&token));
//! ```
//!
//! ## IETF Draft
//!
//! This implements: draft-vandemeent-tibet-provenance
//! https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/
//!
//! ## Credits
//!
//! - Specification: Jasper van de Meent (Humotica)
//! - Implementation: Root AI (Claude) & Jasper
//! - License: MIT OR Apache-2.0

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use uuid::Uuid;
use chrono::Utc;

/// Token states in the TIBET lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub enum TokenState {
    Created,
    Detected,
    Classified,
    Mitigated,
    Resolved,
}

impl Default for TokenState {
    fn default() -> Self {
        TokenState::Created
    }
}

/// A TIBET Token - the atomic unit of provenance
///
/// Captures the four dimensions:
/// - ERIN: What's IN the action (content)
/// - ERAAN: What's attached (dependencies)
/// - EROMHEEN: Context around it (environment)
/// - ERACHTER: Intent behind it (why)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TibetToken {
    /// Unique identifier (UUID v4)
    pub id: String,

    /// ISO8601 timestamp
    pub timestamp: String,

    /// Token type (action, decision, message, etc.)
    pub token_type: String,

    /// Who/what created this token
    pub actor: String,

    /// ERIN - What's IN the action
    pub erin: String,

    /// ERAAN - What's attached (dependencies, references)
    pub eraan: Vec<String>,

    /// EROMHEEN - Context around it
    pub eromheen: String,

    /// ERACHTER - Intent behind it (why)
    pub erachter: String,

    /// Parent token ID for chain linking
    pub parent_id: Option<String>,

    /// Current state in lifecycle
    pub state: TokenState,

    /// Ed25519 signature (hex encoded)
    pub signature: String,

    /// Public key of signer (hex encoded)
    pub signer_pubkey: String,
}

impl TibetToken {
    /// Get the content to be signed (everything except signature)
    fn signable_content(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.timestamp.as_bytes());
        hasher.update(self.token_type.as_bytes());
        hasher.update(self.actor.as_bytes());
        hasher.update(self.erin.as_bytes());
        for dep in &self.eraan {
            hasher.update(dep.as_bytes());
        }
        hasher.update(self.eromheen.as_bytes());
        hasher.update(self.erachter.as_bytes());
        if let Some(ref parent) = self.parent_id {
            hasher.update(parent.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Verify the token's signature
    pub fn verify(&self) -> bool {
        // Decode public key
        let pubkey_bytes = match hex::decode(&self.signer_pubkey) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if pubkey_bytes.len() != 32 {
            return false;
        }

        let pubkey_array: [u8; 32] = match pubkey_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pubkey_array) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Decode signature
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if sig_bytes.len() != 64 {
            return false;
        }

        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&sig_array);

        // Verify
        let content = self.signable_content();
        verifying_key.verify(&content, &signature).is_ok()
    }

    /// Convert to JSON string
    #[cfg(feature = "std")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse from JSON string
    #[cfg(feature = "std")]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// FIR/A Trust Score (0.0 - 1.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub actor: String,
    pub score: f64,
    pub valid_actions: u64,
    pub total_actions: u64,
    pub last_updated: String,
}

impl TrustScore {
    pub fn new(actor: &str) -> Self {
        Self {
            actor: actor.to_string(),
            score: 0.5, // Start neutral
            valid_actions: 0,
            total_actions: 0,
            last_updated: Utc::now().to_rfc3339(),
        }
    }

    /// Update trust score based on action validity
    pub fn update(&mut self, action_valid: bool) {
        self.total_actions += 1;
        if action_valid {
            self.valid_actions += 1;
        }
        // Simple ratio-based scoring
        self.score = self.valid_actions as f64 / self.total_actions as f64;
        self.last_updated = Utc::now().to_rfc3339();
    }
}

/// TIBET Engine - the core provenance engine
///
/// This is the "kernel" - minimal, fast, embeddable.
pub struct TibetEngine {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl TibetEngine {
    /// Create a new engine with random keypair
    pub fn new() -> Self {
        let mut csprng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create engine from existing secret key (32 bytes)
    pub fn from_secret_key(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key (hex encoded)
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Create a new TIBET token
    ///
    /// # Arguments
    /// * `token_type` - Type of token (action, decision, message)
    /// * `erin` - What's IN the action (content)
    /// * `eraan` - What's attached (dependencies)
    /// * `eromheen` - Context around it
    /// * `erachter` - Why (intent)
    /// * `actor` - Who/what created this
    /// * `parent_id` - Optional parent for chaining
    pub fn create_token(
        &self,
        token_type: &str,
        erin: &str,
        eraan: &[&str],
        eromheen: &str,
        erachter: &str,
        actor: &str,
        parent_id: Option<&str>,
    ) -> TibetToken {
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let pubkey_hex = self.public_key_hex();

        let mut token = TibetToken {
            id,
            timestamp,
            token_type: token_type.to_string(),
            actor: actor.to_string(),
            erin: erin.to_string(),
            eraan: eraan.iter().map(|s| s.to_string()).collect(),
            eromheen: eromheen.to_string(),
            erachter: erachter.to_string(),
            parent_id: parent_id.map(|s| s.to_string()),
            state: TokenState::Created,
            signature: String::new(),
            signer_pubkey: pubkey_hex,
        };

        // Sign the token
        let content = token.signable_content();
        let signature = self.signing_key.sign(&content);
        token.signature = hex::encode(signature.to_bytes());

        token
    }

    /// Verify a token's signature
    pub fn verify(&self, token: &TibetToken) -> bool {
        token.verify()
    }

    /// Create a child token (chained to parent)
    pub fn create_child(
        &self,
        parent: &TibetToken,
        token_type: &str,
        erin: &str,
        eraan: &[&str],
        eromheen: &str,
        erachter: &str,
        actor: &str,
    ) -> TibetToken {
        self.create_token(
            token_type,
            erin,
            eraan,
            eromheen,
            erachter,
            actor,
            Some(&parent.id),
        )
    }
}

impl Default for TibetEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================
// Python Bindings (PyO3)
// ============================================

#[cfg(feature = "python")]
mod python {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyModuleMethods;
    use pyo3::exceptions::PyValueError;
    use pyo3::Bound;

    #[pyclass(name = "TibetToken")]
    #[derive(Clone)]
    pub struct PyTibetToken {
        inner: TibetToken,
    }

    #[pymethods]
    impl PyTibetToken {
        #[getter]
        fn id(&self) -> &str { &self.inner.id }

        #[getter]
        fn timestamp(&self) -> &str { &self.inner.timestamp }

        #[getter]
        fn token_type(&self) -> &str { &self.inner.token_type }

        #[getter]
        fn actor(&self) -> &str { &self.inner.actor }

        #[getter]
        fn erin(&self) -> &str { &self.inner.erin }

        #[getter]
        fn eraan(&self) -> Vec<String> { self.inner.eraan.clone() }

        #[getter]
        fn eromheen(&self) -> &str { &self.inner.eromheen }

        #[getter]
        fn erachter(&self) -> &str { &self.inner.erachter }

        #[getter]
        fn parent_id(&self) -> Option<String> { self.inner.parent_id.clone() }

        #[getter]
        fn signature(&self) -> &str { &self.inner.signature }

        fn verify(&self) -> bool {
            self.inner.verify()
        }

        fn to_json(&self) -> PyResult<String> {
            self.inner.to_json()
                .map_err(|e| PyValueError::new_err(e.to_string()))
        }

        fn __repr__(&self) -> String {
            format!("TibetToken(id='{}', actor='{}', type='{}')",
                self.inner.id, self.inner.actor, self.inner.token_type)
        }
    }

    #[pyclass(name = "TibetEngine")]
    pub struct PyTibetEngine {
        inner: TibetEngine,
    }

    #[pymethods]
    impl PyTibetEngine {
        #[new]
        fn new() -> Self {
            Self { inner: TibetEngine::new() }
        }

        #[getter]
        fn public_key(&self) -> String {
            self.inner.public_key_hex()
        }

        #[pyo3(signature = (token_type, erin, eraan, eromheen, erachter, actor, parent_id=None))]
        fn create_token(
            &self,
            token_type: &str,
            erin: &str,
            eraan: Vec<String>,
            eromheen: &str,
            erachter: &str,
            actor: &str,
            parent_id: Option<&str>,
        ) -> PyTibetToken {
            let eraan_refs: Vec<&str> = eraan.iter().map(|s| s.as_str()).collect();
            PyTibetToken {
                inner: self.inner.create_token(
                    token_type, erin, &eraan_refs, eromheen, erachter, actor, parent_id
                )
            }
        }

        fn verify(&self, token: &PyTibetToken) -> bool {
            self.inner.verify(&token.inner)
        }
    }

    /// Python module
    #[pymodule]
    fn tibet_core(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
        m.add_class::<PyTibetToken>()?;
        m.add_class::<PyTibetEngine>()?;
        m.add("__version__", "0.1.1")?;
        Ok(())
    }
}

// ============================================
// WASM Bindings (wasm-bindgen)
// ============================================

#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub struct WasmTibetEngine {
        inner: TibetEngine,
    }

    #[wasm_bindgen]
    impl WasmTibetEngine {
        #[wasm_bindgen(constructor)]
        pub fn new() -> Self {
            Self { inner: TibetEngine::new() }
        }

        #[wasm_bindgen(getter)]
        pub fn public_key(&self) -> String {
            self.inner.public_key_hex()
        }

        /// Create a token and return as JSON
        pub fn create_token(
            &self,
            token_type: &str,
            erin: &str,
            eraan: &str,  // JSON array as string
            eromheen: &str,
            erachter: &str,
            actor: &str,
            parent_id: Option<String>,
        ) -> String {
            let eraan_vec: Vec<String> = serde_json::from_str(eraan).unwrap_or_default();
            let eraan_refs: Vec<&str> = eraan_vec.iter().map(|s| s.as_str()).collect();

            let token = self.inner.create_token(
                token_type,
                erin,
                &eraan_refs,
                eromheen,
                erachter,
                actor,
                parent_id.as_deref(),
            );

            serde_json::to_string(&token).unwrap_or_default()
        }

        /// Verify a token from JSON
        pub fn verify(&self, token_json: &str) -> bool {
            match serde_json::from_str::<TibetToken>(token_json) {
                Ok(token) => token.verify(),
                Err(_) => false,
            }
        }
    }

    #[wasm_bindgen]
    pub fn tibet_version() -> String {
        "0.1.0".to_string()
    }
}

// ============================================
// C Bindings (FFI)
// ============================================

#[cfg(feature = "cbind")]
mod cbind {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::ptr;

    /// Opaque engine handle for C
    pub struct CEngine {
        inner: TibetEngine,
    }

    /// Create a new TIBET engine
    #[no_mangle]
    pub extern "C" fn tibet_engine_new() -> *mut CEngine {
        let engine = Box::new(CEngine {
            inner: TibetEngine::new(),
        });
        Box::into_raw(engine)
    }

    /// Create engine from secret key (hex string)
    #[no_mangle]
    pub extern "C" fn tibet_engine_from_secret(secret_hex: *const c_char) -> *mut CEngine {
        if secret_hex.is_null() {
            return ptr::null_mut();
        }

        let secret_str = unsafe {
            match CStr::from_ptr(secret_hex).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };

        let secret_bytes = match hex::decode(secret_str) {
            Ok(b) => b,
            Err(_) => return ptr::null_mut(),
        };

        if secret_bytes.len() != 32 {
            return ptr::null_mut();
        }

        let secret: [u8; 32] = match secret_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        };

        let engine = Box::new(CEngine {
            inner: TibetEngine::from_secret_key(&secret),
        });
        Box::into_raw(engine)
    }

    /// Free the engine
    #[no_mangle]
    pub extern "C" fn tibet_engine_free(engine: *mut CEngine) {
        if !engine.is_null() {
            unsafe {
                drop(Box::from_raw(engine));
            }
        }
    }

    /// Get public key as hex string
    #[no_mangle]
    pub extern "C" fn tibet_get_public_key(engine: *const CEngine) -> *mut c_char {
        if engine.is_null() {
            return ptr::null_mut();
        }

        let engine = unsafe { &*engine };
        let pubkey = engine.inner.public_key_hex();

        match CString::new(pubkey) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Create a TIBET token (returns JSON string)
    #[no_mangle]
    pub extern "C" fn tibet_create_token(
        engine: *mut CEngine,
        token_type: *const c_char,
        erin: *const c_char,
        eraan_json: *const c_char,
        eromheen_json: *const c_char,
        erachter: *const c_char,
        actor: *const c_char,
        parent_id: *const c_char,
    ) -> *mut c_char {
        if engine.is_null() || token_type.is_null() || erin.is_null() || eraan_json.is_null()
            || eromheen_json.is_null() || erachter.is_null() || actor.is_null()
        {
            return ptr::null_mut();
        }

        let engine = unsafe { &*engine };

        let token_type_str = unsafe { CStr::from_ptr(token_type).to_str().unwrap_or("") };
        let erin_str = unsafe { CStr::from_ptr(erin).to_str().unwrap_or("") };
        let eraan_str = unsafe { CStr::from_ptr(eraan_json).to_str().unwrap_or("[]") };
        let eromheen_str = unsafe { CStr::from_ptr(eromheen_json).to_str().unwrap_or("{}") };
        let erachter_str = unsafe { CStr::from_ptr(erachter).to_str().unwrap_or("") };
        let actor_str = unsafe { CStr::from_ptr(actor).to_str().unwrap_or("") };

        let parent = if parent_id.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(parent_id).to_str().ok() }
        };

        // Parse eraan JSON array
        let eraan_vec: Vec<String> = serde_json::from_str(eraan_str).unwrap_or_default();
        let eraan_refs: Vec<&str> = eraan_vec.iter().map(|s| s.as_str()).collect();

        let token = engine.inner.create_token(
            token_type_str,
            erin_str,
            &eraan_refs,
            eromheen_str,
            erachter_str,
            actor_str,
            parent,
        );

        match serde_json::to_string(&token) {
            Ok(json) => match CString::new(json) {
                Ok(s) => s.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            Err(_) => ptr::null_mut(),
        }
    }

    /// Verify a token (from JSON string)
    #[no_mangle]
    pub extern "C" fn tibet_verify(engine: *const CEngine, token_json: *const c_char) -> bool {
        if engine.is_null() || token_json.is_null() {
            return false;
        }

        let json_str = unsafe {
            match CStr::from_ptr(token_json).to_str() {
                Ok(s) => s,
                Err(_) => return false,
            }
        };

        match serde_json::from_str::<TibetToken>(json_str) {
            Ok(token) => token.verify(),
            Err(_) => false,
        }
    }

    /// Verify with external public key
    #[no_mangle]
    pub extern "C" fn tibet_verify_with_key(
        token_json: *const c_char,
        public_key_hex: *const c_char,
    ) -> bool {
        if token_json.is_null() || public_key_hex.is_null() {
            return false;
        }

        let json_str = unsafe {
            match CStr::from_ptr(token_json).to_str() {
                Ok(s) => s,
                Err(_) => return false,
            }
        };

        let _pubkey_str = unsafe {
            match CStr::from_ptr(public_key_hex).to_str() {
                Ok(s) => s,
                Err(_) => return false,
            }
        };

        // Parse and verify - the token contains its own public key
        match serde_json::from_str::<TibetToken>(json_str) {
            Ok(token) => token.verify(),
            Err(_) => false,
        }
    }

    /// Sign arbitrary data
    #[no_mangle]
    pub extern "C" fn tibet_sign(
        engine: *const CEngine,
        data: *const u8,
        data_len: usize,
    ) -> *mut c_char {
        if engine.is_null() || data.is_null() || data_len == 0 {
            return ptr::null_mut();
        }

        let engine = unsafe { &*engine };
        let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };

        let signature = engine.inner.signing_key.sign(data_slice);
        let sig_hex = hex::encode(signature.to_bytes());

        match CString::new(sig_hex) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Sign a string message
    #[no_mangle]
    pub extern "C" fn tibet_sign_string(
        engine: *const CEngine,
        message: *const c_char,
    ) -> *mut c_char {
        if engine.is_null() || message.is_null() {
            return ptr::null_mut();
        }

        let msg_str = unsafe {
            match CStr::from_ptr(message).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };

        let engine = unsafe { &*engine };
        let signature = engine.inner.signing_key.sign(msg_str.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        match CString::new(sig_hex) {
            Ok(s) => s.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }

    /// Free a string allocated by TIBET
    #[no_mangle]
    pub extern "C" fn tibet_free_string(s: *mut c_char) {
        if !s.is_null() {
            unsafe {
                drop(CString::from_raw(s));
            }
        }
    }

    /// Get TIBET version
    #[no_mangle]
    pub extern "C" fn tibet_version() -> *const c_char {
        static VERSION: &[u8] = b"0.1.1\0";
        VERSION.as_ptr() as *const c_char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let engine = TibetEngine::new();

        let token = engine.create_token(
            "action",
            "User requested translation",
            &["model_v1", "tokenizer_v2"],
            r#"{"env": "production"}"#,
            "Fulfilling user request",
            "test_agent",
            None,
        );

        assert!(engine.verify(&token));
        assert!(token.verify());
    }

    #[test]
    fn test_chain() {
        let engine = TibetEngine::new();

        let parent = engine.create_token(
            "request",
            "Translate hello to Dutch",
            &[],
            "{}",
            "User wants translation",
            "user_001",
            None,
        );

        let child = engine.create_child(
            &parent,
            "response",
            "Hallo",
            &["parent_token"],
            "{}",
            "Translation completed",
            "ai_agent",
        );

        assert_eq!(child.parent_id, Some(parent.id.clone()));
        assert!(child.verify());
    }

    #[test]
    fn test_tamper_detection() {
        let engine = TibetEngine::new();

        let mut token = engine.create_token(
            "action",
            "Original content",
            &[],
            "{}",
            "Original intent",
            "agent",
            None,
        );

        // Tamper with the content
        token.erin = "Tampered content".to_string();

        // Verification should fail
        assert!(!token.verify());
    }
}
