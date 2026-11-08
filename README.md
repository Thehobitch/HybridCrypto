# HybridCrypto

A minimal, efficient hybrid signature library (ECDSA-P256 + ML-DSA-65) for Apple platforms 26+.

## Design goals
- Thin hot path (local CryptoKit by default)
- Optional driver abstraction for HSMs (nShield REST skeleton included)
- Typed errors that distinguish classical vs post-quantum failures
- Optional domain-separation context for ML-DSA
- Thin Secure Enclave hybrid path when hardware supports it

## Requirements
- iOS 26 / macOS 26 / etc. (CryptoKit ML-DSA)

## Usage

```swift
import HybridCrypto

// Local (zero-overhead)
let (ecKey, pqKey) = try HybridCrypto.generateKeyPair()
let message = Data("payload".utf8)
let signature = try HybridCrypto.sign(message: message, classicalKey: ecKey, pqKey: pqKey)
let valid = try HybridCrypto.verify(signature, message: message,
                                    classicalPublic: ecKey.publicKey,
                                    pqPublic: pqKey.publicKey)
```

See `HybridCrypto.swift` for the full API, Secure Enclave helpers, and the `NShieldRESTDriver` skeleton.
