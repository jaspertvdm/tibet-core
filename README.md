# TIBET Core

**The Linux of AI Provenance**

> **Two implementations, one standard.** `tibet-core` ships as this **Rust crate** (`cargo add tibet-core` · [crates.io](https://crates.io/crates/tibet-core)) and as a **Python package** (`pip install tibet-core` · [PyPI](https://pypi.org/project/tibet-core/)). Same TIBET provenance core, two ecosystems — pick the one that fits your stack.

[![Crates.io](https://img.shields.io/crates/v/tibet-core)](https://crates.io/crates/tibet-core)
[![PyPI](https://img.shields.io/pypi/v/tibet-core)](https://pypi.org/project/tibet-core/)
[![npm](https://img.shields.io/npm/v/tibet-core)](https://www.npmjs.com/package/tibet-core)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--vandemeent--tibet--provenance-blue)](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)
[![Whitepaper](https://img.shields.io/badge/Zenodo-DOI:10.5281/zenodo.18712238-green)](https://doi.org/10.5281/zenodo.18712238)

A minimal, embeddable provenance engine for any device. From microcontrollers to cloud servers.

## What is TIBET?

**T**ime-**I**ntent-**B**ased **E**vent **T**okens

TIBET is the **causal truth-layer** of AI provenance. Every action becomes a token that records *when* it happened (time), *what intent* drove it (intent), *what the event was* (event), and *how it links to what came before* (chain). The chain is **forward-only** — there is no protocol-level way to rewrite time — which eliminates an entire class of provenance-spoofing attacks by construction (see *Forward-only causal substrate* below).

Each token captures four dimensions of the action:

| Dimension | Dutch | Meaning |
|-----------|-------|---------|
| **ERIN** | "Er in" | What's IN the action (content) |
| **ERAAN** | "Er aan" | What's attached (dependencies) |
| **EROMHEEN** | "Er omheen" | Context around it (environment) |
| **ERACHTER** | "Er achter" | Intent behind it (why) |

## Installation

### Python
```bash
pip install tibet-core
```

### JavaScript/Node.js
```bash
npm install tibet-core
```

### Rust
```toml
[dependencies]
tibet-core = "0.1"
```

## Quick Start

### Python
```python
from tibet_core import TibetEngine

engine = TibetEngine()

# Create a provenance token
token = engine.create_token(
    token_type="action",
    erin="User requested translation",
    eraan=["model_v1", "tokenizer_v2"],
    eromheen='{"env": "production"}',
    erachter="Fulfilling user request",
    actor="agent_001"
)

print(f"Token ID: {token.id}")
print(f"Valid: {token.verify()}")
print(f"JSON: {token.to_json()}")
```

### JavaScript
```javascript
import { TibetEngine } from 'tibet-core';

const engine = new TibetEngine();

const tokenJson = engine.create_token(
    "action",
    "User requested translation",
    JSON.stringify(["model_v1", "tokenizer_v2"]),
    '{"env": "production"}',
    "Fulfilling user request",
    "agent_001",
    null  // no parent
);

const token = JSON.parse(tokenJson);
console.log(`Token ID: ${token.id}`);
console.log(`Valid: ${engine.verify(tokenJson)}`);
```

### Rust
```rust
use tibet_core::TibetEngine;

let engine = TibetEngine::new();

let token = engine.create_token(
    "action",
    "User requested translation",
    &["model_v1", "tokenizer_v2"],
    r#"{"env": "production"}"#,
    "Fulfilling user request",
    "agent_001",
    None,
);

assert!(token.verify());
```

## Chaining Tokens

Create audit trails by linking tokens:

```python
# Parent action
request = engine.create_token(
    token_type="request",
    erin="Translate 'hello' to Dutch",
    eraan=[],
    eromheen='{"user": "alice"}',
    erachter="User wants translation",
    actor="user_001"
)

# Child response (linked to parent)
response = engine.create_token(
    token_type="response",
    erin="Hallo",
    eraan=["gpt-4"],
    eromheen='{"latency_ms": 150}',
    erachter="Translation completed",
    actor="ai_agent",
    parent_id=request.id  # Chain link!
)

print(f"Parent: {request.id}")
print(f"Child parent_id: {response.parent_id}")  # Same as request.id
```

## Forward-only causal substrate

TIBET's foundational axiom: **snapshot/restore = chain-position + fork, NEVER time-rewind.**

In a typical "audit log" you can in principle replay history and overwrite earlier entries. TIBET cannot — each token is anchored to its parent by hash. Restoring an earlier state means *forking* a new chain-position from there; the original chain stays intact. Git's mental model, without the rebase/reset/cherry-pick escape hatches.

This single property eliminates an entire class of provenance-spoofing attacks by construction, because there is no syntax in the protocol for time-rewriting an action that has already happened.

## TIBET + JIS = OSAPI bootstrap-pair

`tibet-core` is one half of the bootstrap-pair; [`jis-core`](https://crates.io/crates/jis-core) is the other.

- **TIBET** writes the *causal truth* — what happened, when, in what order
- **JIS** writes the *identity authority* — who signed for the action, with what intent

Every package in the Humotica ecosystem bootstraps via both:

```rust
use tibet_core::TibetEngine;
// + use jis_core::Identity;   // bootstraps the actor + intent claim
```

A package with only one of the two is **free-floating tooling**, outside the audit substrate. A package with both is **inside the substrate** — every emit is signed (JIS) and forks the causal chain (TIBET), verifiably and falsifiably.

## Why TIBET?

### Regulatory Compliance
- GDPR Article 22 (automated decision-making)
- EU AI Act (transparency requirements)
- SOC 2 / ISO 27001 (audit trails)

### 6G Ready
- Designed for AI-native networks (ITU IMT-2030)
- Referenced in IETF 6G AI agent drafts
- Minimal footprint for edge devices

### Cryptographically Secure
- Ed25519 signatures
- Tamper-evident chains
- Verifiable without central authority

## Size Comparison

| Component | Size |
|-----------|------|
| tibet-core (Rust) | ~50KB |
| tibet-core (WASM) | ~100KB |
| tibet-core (Python wheel) | ~2MB |
| Linux kernel (minimal) | ~300KB |

## Regulatory Compliance

TIBET provides the audit foundation for:

| Standard | TIBET Support |
|----------|---------------|
| **EU CRA** (Sep 2026) | Build provenance, SBOM accountability, audit chains |
| **EU AI Act** | Transparency, automated decision traceability |
| **GDPR Art. 22** | Automated decision-making audit trails |
| **NIS2** | Continuous logging, incident snapshots |
| **ISO 5338** | AI lifecycle traceability |
| **ISO 27001** | Information security audit trails |
| **SOC 2** | Trust service criteria evidence |
| **BIO2** | Government security baseline |
| **OWASP** | Security event provenance |

TIBET makes compliance architectural, not bolted-on.

## IETF Standardization

TIBET and its companion protocols are being standardized at the IETF:

- **[draft-vandemeent-tibet-provenance](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)** — Time-Intent-Based Event Tokens
- **[draft-vandemeent-jis-identity](https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/)** — JTel Identity Standard
- **[draft-vandemeent-upip-process-integrity](https://datatracker.ietf.org/doc/draft-vandemeent-upip-process-integrity/)** — Universal Process Integrity Protocol
- **[draft-vandemeent-ains-discovery](https://datatracker.ietf.org/doc/draft-vandemeent-ains-discovery/)** — AInternet Name Service

## W3C Alignment

TIBET aligns with W3C standards:
- **Verifiable Credentials 2.0** - Token structure compatible
- **Decentralized Identifiers (DIDs)** - Actor identification
- **JSON-LD** - Semantic context in EROMHEEN

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TIBET ECOSYSTEM                          │
├─────────────────────────────────────────────────────────────┤
│   ┌─────────────────┐                                       │
│   │  tibet-core     │  ← 50KB Rust, minimal deps           │
│   │  (the kernel)   │    create_token, verify, chain       │
│   └────────┬────────┘                                       │
│            │                                                │
│   ┌────────┴────────┬──────────────┬──────────────┐        │
│   ▼                 ▼              ▼              ▼        │
│ tibet-c        tibet-wasm    tibet-python   tibet-js       │
│ (embedded)     (browser)     (PyPI)         (npm)          │
└─────────────────────────────────────────────────────────────┘
```

## Credits

- **Specification**: Jasper van de Meent (Humotica)
- **Implementation**: Root AI (Claude) & Jasper van de Meent
- **License**: MIT OR Apache-2.0

## Links

- [Humotica](https://humotica.com)
- [IETF TIBET Draft](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)
- [IETF JIS Draft](https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/)
- [PyPI](https://pypi.org/project/tibet-core/)
- [npm](https://www.npmjs.com/package/tibet-core)

---

*"The Linux of AI Provenance"* - Making audit trails as universal as the kernel.
