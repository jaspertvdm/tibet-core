# TIBET Core

**The Linux of AI Provenance**

[![PyPI](https://img.shields.io/pypi/v/tibet-core)](https://pypi.org/project/tibet-core/)
[![npm](https://img.shields.io/npm/v/tibet-core)](https://www.npmjs.com/package/tibet-core)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--vandemeent--tibet--provenance-blue)](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)

A minimal, embeddable provenance engine for any device. From microcontrollers to cloud servers.

## What is TIBET?

**T**ransaction/**I**nteraction-**B**ased **E**vidence **T**rail

TIBET captures the four dimensions of every AI action:

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

## IETF Standardization

TIBET is being standardized at the IETF:

- **[draft-vandemeent-tibet-provenance](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/)** - Evidence Trail Protocol
- **[draft-vandemeent-jis-identity](https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/)** - JTel Identity Standard

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
