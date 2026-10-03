# CryptoSwift Repository Guidelines

## Project Facts

- This Swift package provides Salsa20 and RIPEMD-128 for the local dictionary toolchain.
- `Package.swift` defines the `CryptoSwift` library and `CryptoSwiftTests` target; the minimum tools version is Swift 6.2.
- Implementations are in `Sources/CryptoSwift/Salsa20Swift.swift` and `Sources/CryptoSwift/RIPEMD128.swift`.
- `Tests/CryptoSwiftTests/` uses Swift Testing for reference vectors, round trips, and dictionary decryption behavior.

## Commands

- `swift build` — compile the library.
- `swift test` — run package tests; use `--filter <test-name>` for a focused check.
- Open `Package.swift` in Xcode when using the IDE.

## Algorithm Boundaries

- Salsa20 accepts 16- or 32-byte keys, an 8-byte nonce, and a positive even round count. Preserve counter and byte-order semantics when changing the implementation.
- Check algorithm changes against published vectors for the affected algorithm and existing dictionary decryption tests; a round trip alone cannot prove compatibility.
- Fixtures may contain public reference vectors or synthetic keys and nonces. Never record real credentials or private dictionary payloads.
