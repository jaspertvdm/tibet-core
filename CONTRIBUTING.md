# Contributing to TIBET Core

The Linux of AI Provenance. Contributions welcome!

## How to Contribute

1. **Fork** this repository
2. **Clone** your fork locally
3. **Create a branch** for your changes
4. **Make your changes**
5. **Test** your changes
6. **Submit a Pull Request**

## Development Setup

### Rust
```bash
git clone https://github.com/YOUR_USERNAME/tibet-core.git
cd tibet-core
cargo build
cargo test
```

### Python bindings
```bash
pip install maturin
maturin develop
pytest
```

## What We Need Help With

### Core Engine (Rust)
- Performance optimizations
- Additional hash algorithms
- Hardware security module (HSM) support
- WASM improvements

### Language Bindings
- Go bindings
- Java bindings
- Swift bindings
- Improved TypeScript types

### Standards
- IETF draft feedback
- W3C alignment
- Test vectors
- Interop testing

### Documentation
- More examples
- Architecture docs
- Security analysis

## Code Style

### Rust
- Follow rustfmt
- No unsafe unless necessary
- Document public items
- Keep no_std compatible

### Python
- Follow PEP 8
- Type hints
- Docstrings

## The Philosophy

TIBET is about **trust through transparency**. Every action should be auditable. The Dutch semantics (ERIN, ERAAN, EROMHEEN, ERACHTER) force you to think about:
- What's **IN** the action
- What it's **attached to**
- What's **around** it
- What's **behind** it (intent)

When adding features, ask: does this help answer "what happened and why?"

## Testing

```bash
# Rust
cargo test

# Python
pytest python/tests/

# All
./test_all.sh
```

## Questions?

- Open an issue
- Email: jasper@humotica.com
- IETF mailing list for spec questions

## License

By contributing, you agree that your contributions will be licensed under MIT OR Apache-2.0.
