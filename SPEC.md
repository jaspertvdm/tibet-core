# TIBET Specification

**Token-based Intent, Behavior, Evidence & Trust**

Version: 0.2.0
Status: Stable
Authors: J. van de Meent, R. AI
IETF: draft-vandemeent-tibet-provenance

## Abstract

TIBET is a provenance framework that embeds audit capability into actions rather than monitoring traffic. Every operation produces a cryptographic token capturing what happened, what it relates to, the context, and the intent.

## 1. Core Concepts

### 1.1 The Problem

Traditional security audits network traffic:
```
[Application] → [Firewall] → [Log] → "What went over the wire?"
```

This misses intent. You see packets, not purpose.

### 1.2 The Solution

TIBET embeds provenance into actions:
```
[Application + TIBET] → Token → "What happened and why?"
```

Every function call, decision, or transformation creates a token with cryptographic integrity.

## 2. Token Structure

### 2.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (UUID v4) |
| `token_type` | string | Type of action (e.g., "action", "request", "response") |
| `timestamp` | string | ISO 8601 format |
| `actor` | string | Who/what performed the action (JIS format) |
| `content_hash` | string | SHA-256 of token content |

### 2.2 Provenance Fields (Dutch Semantics)

| Field | Dutch | Type | Description |
|-------|-------|------|-------------|
| `erin` | "in it" | string | Content/data of the action |
| `eraan` | "attached to it" | array | References, dependencies |
| `eromheen` | "around it" | string (JSON) | Context, environment |
| `erachter` | "behind it" | string | Intent, reason |

### 2.3 Chain Fields

| Field | Type | Description |
|-------|------|-------------|
| `parent_id` | string? | Parent token for linking |
| `signature` | string? | Ed25519 signature |

## 3. Hash Computation

The `content_hash` is computed as:

```
content_hash = SHA256(
    id || token_type || timestamp || actor ||
    erin || eraan || eromheen || erachter || parent_id
)
```

Verification: recompute hash and compare.

## 4. Signature (Optional)

Ed25519 signature over the content_hash:

```
signature = Ed25519.sign(content_hash, private_key)
```

Verification:
```
Ed25519.verify(content_hash, signature, public_key)
```

## 5. Chain Semantics

Tokens form chains via `parent_id`:

```
Token A (root)
    ↓
Token B (parent_id = A.id)
    ↓
Token C (parent_id = B.id)
```

Chain traversal: follow `parent_id` backwards until null.

## 6. Actor Identification

Actors should use JIS (JTel Identity Standard) format:

```
jis:domain:identifier

Examples:
jis:humotica:web_app
jis:humotica:user:alice
jis:external:api:partner
```

## 7. Compliance Mapping

### ISO 5338 (AI Management)
- Token chains = decision traceability
- `erachter` field = intent documentation

### NIS2 (EU Cybersecurity)
- Continuous logging via token streams
- Chain verification = incident reconstruction

### EU AI Act
- GDPR Article 22 compliance
- Automated decision transparency

## 8. Wire Format

### JSON
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "token_type": "action",
  "timestamp": "2026-02-20T14:30:00Z",
  "actor": "jis:app:web",
  "erin": "User login request",
  "eraan": ["auth_service"],
  "eromheen": "{\"ip\": \"192.168.1.1\"}",
  "erachter": "Authenticate user",
  "parent_id": null,
  "content_hash": "a1b2c3...",
  "signature": null
}
```

### Binary (Compact)
For embedded devices, a compact binary format is available using MessagePack.

## 9. Language Bindings

| Language | Package | no_std | Signing |
|----------|---------|--------|---------|
| Rust | tibet-core | Yes | Ed25519 |
| Python | tibet-core (PyPI) | N/A | Planned |
| JavaScript | tibet-core (npm) | N/A | Planned |
| C | cbind/ | Yes | Ed25519 |

## 10. IETF Status

- Draft: draft-vandemeent-tibet-provenance
- Status: Individual submission
- Target: Proposed Standard

## License

MIT OR Apache-2.0

## Contact

- Email: jasper@humotica.com
- Web: https://humotica.com
