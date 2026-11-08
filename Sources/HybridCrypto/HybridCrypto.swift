// SPDX-FileCopyrightText: © 2026 Hybrid Crypto Example
// SPDX-License-Identifier: CC-BY-4.0
//
// This software is licensed under the Creative Commons Attribution 4.0 International License.
// You may share and adapt it for any purpose, even commercially, as long as you give appropriate credit.
// Full license: https://creativecommons.org/licenses/by/4.0/
//
// Note: Creative Commons licenses are generally recommended for content rather than source code.
// For production software, consider a standard open-source license such as MIT or Apache-2.0.
// This file uses CC BY 4.0 as requested.

import Foundation
import CryptoKit

// MARK: - Design Requirements
/// Core requirements for this hybrid cryptographic software:
///
/// 1. Efficiency
///    - Minimize allocations and copies of key material and signatures.
///    - Prefer fixed-size operations and avoid unnecessary intermediate structures.
///    - Keep the hot path (sign/verify) as thin as possible.
///    - Support hardware-accelerated paths (CryptoKit, nShield FPGA/PQC) without extra abstraction cost.
///
/// 2. Simplicity
///    - Small, obvious API surface.
///    - One clear way to do hybrid sign/verify/keygen.
///    - Drivers are optional; the default path stays local and direct.
///    - No configuration ceremony for common use cases.
///    - Code should be readable in a single pass.

// MARK: - Errors
public enum HybridCryptoError: Error, Equatable {
    /// Classical (ECDSA-P256) key or operation failed.
    case classical(ClassicalError)
    /// Post-quantum (ML-DSA-65) key or operation failed.
    case postQuantum(PostQuantumError)
    /// Hybrid-level failure (both sides or structure).
    case hybrid(HybridError)
    /// Secure Enclave is unavailable or rejected the operation.
    case secureEnclaveUnavailable
    /// Driver / remote backend failure.
    case driver(CryptoDriverError)
}

public enum ClassicalError: Error, Equatable {
    case keyGenerationFailed(String)
    case invalidKeyMaterial
    case signingFailed(String)
    case invalidSignatureFormat
    case verificationFailed
}

public enum PostQuantumError: Error, Equatable {
    case keyGenerationFailed(String)
    case invalidKeyMaterial
    case signingFailed(String)
    case invalidSignatureFormat
    case verificationFailed
    case contextRejected
}

public enum HybridError: Error, Equatable {
    case algorithmMismatch
    case messageMismatch
    case incompleteSignature
    case bothSidesFailed
}

// MARK: - Core Types (kept minimal)
public struct HybridSignature {
    public let pqSignature: Data
    public let classicalSignature: Data
    public let message: Data
    public let algorithm: String
    public let context: Data?

    public var combined: Data { pqSignature + classicalSignature }

    public init(pqSignature: Data, classicalSignature: Data, message: Data,
                algorithm: String, context: Data? = nil) {
        self.pqSignature = pqSignature
        self.classicalSignature = classicalSignature
        self.message = message
        self.algorithm = algorithm
        self.context = context
    }
}

public struct HybridKeyHandle {
    public let identifier: String
    public let classicalPublic: Data
    public let pqPublic: Data

    public init(identifier: String, classicalPublic: Data, pqPublic: Data) {
        self.identifier = identifier
        self.classicalPublic = classicalPublic
        self.pqPublic = pqPublic
    }
}

// MARK: - Simple Direct API (default, most efficient path)
/// Prefer this for local use. Zero driver overhead.
@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
public struct HybridCrypto {
    public static let algorithm = "ECDSA-P256+ML-DSA-65"
    private let driver: any CryptoDriver

    /// Driver-backed operations are explicitly selected; static operations stay local.
    public init(driver: any CryptoDriver) {
        self.driver = driver
    }

    public func generateKeyPair() throws -> HybridKeyHandle {
        try driver.generateHybridKeyPair()
    }

    public func sign(key: HybridKeyHandle, message: Data, context: Data? = nil) throws -> HybridSignature {
        try driver.hybridSign(identifier: key.identifier, message: message, context: context)
    }

    /// Verify locally with trusted public keys, including signatures from remote drivers.
    public func verify(_ signature: HybridSignature, message: Data,
                       key: HybridKeyHandle, context: Data? = nil) throws -> Bool {
        try Self.verify(signature, message: message,
                        classicalPublic: try Self.makeClassicalPublic(key.classicalPublic),
                        pqPublic: try Self.makePQPublic(key.pqPublic),
                        context: context ?? signature.context)
    }

    // MARK: Local key generation
    public static func generateKeyPair() throws -> (classical: P256.Signing.PrivateKey, pq: MLDSA65.PrivateKey) {
        let classical: P256.Signing.PrivateKey
        do {
            classical = P256.Signing.PrivateKey()
        } catch {
            throw HybridCryptoError.classical(.keyGenerationFailed(error.localizedDescription))
        }

        let pq: MLDSA65.PrivateKey
        do {
            pq = try MLDSA65.PrivateKey()
        } catch {
            throw HybridCryptoError.postQuantum(.keyGenerationFailed(error.localizedDescription))
        }
        return (classical, pq)
    }

    // MARK: Local hybrid sign
    /// Hybrid sign. Both signatures are produced; verification requires both.
    /// Optional `context` is passed only to the ML-DSA signature for domain separation.
    public static func sign(message: Data,
                            classicalKey: P256.Signing.PrivateKey,
                            pqKey: MLDSA65.PrivateKey,
                            context: Data? = nil) throws -> HybridSignature {
        let pqSig: Data
        do {
            pqSig = try pqKey.signature(for: message, context: context)
        } catch {
            throw HybridCryptoError.postQuantum(.signingFailed(error.localizedDescription))
        }
        guard !pqSig.isEmpty else {
            throw HybridCryptoError.postQuantum(.invalidSignatureFormat)
        }

        let ecSig: Data
        do {
            ecSig = try classicalKey.signature(for: message).rawRepresentation
        } catch {
            throw HybridCryptoError.classical(.signingFailed(error.localizedDescription))
        }
        guard ecSig.count == 64 else {
            throw HybridCryptoError.classical(.invalidSignatureFormat)
        }

        return HybridSignature(
            pqSignature: pqSig,
            classicalSignature: ecSig,
            message: message,
            algorithm: Self.algorithm,
            context: context
        )
    }

    // MARK: Local hybrid verify
    /// Hybrid verify. Returns true only if both classical and PQC signatures are valid.
    public static func verify(_ signature: HybridSignature,
                              message: Data,
                              classicalPublic: P256.Signing.PublicKey,
                              pqPublic: MLDSA65.PublicKey,
                              context: Data? = nil) throws -> Bool {
        guard signature.algorithm == Self.algorithm else {
            throw HybridCryptoError.hybrid(.algorithmMismatch)
        }
        guard signature.message == message else {
            throw HybridCryptoError.hybrid(.messageMismatch)
        }
        guard !signature.pqSignature.isEmpty, signature.classicalSignature.count == 64 else {
            throw HybridCryptoError.hybrid(.incompleteSignature)
        }

        let effectiveContext = context ?? signature.context

        let isValidPQ: Bool
        do {
            isValidPQ = try pqPublic.isValidSignature(signature.pqSignature, for: message, context: effectiveContext)
        } catch {
            throw HybridCryptoError.postQuantum(.verificationFailed)
        }

        let isValidEC: Bool
        do {
            let ecSig = try P256.Signing.ECDSASignature(rawRepresentation: signature.classicalSignature)
            isValidEC = classicalPublic.isValidSignature(ecSig, for: message)
        } catch {
            throw HybridCryptoError.classical(.verificationFailed)
        }

        if !isValidPQ && !isValidEC {
            throw HybridCryptoError.hybrid(.bothSidesFailed)
        }
        return isValidPQ && isValidEC
    }

    // MARK: - Secure Enclave hybrid path (thin, hardware-backed when available)
    /// Generate hybrid keys backed by the Secure Enclave when supported.
    /// Falls back is the caller's responsibility; this throws if Secure Enclave is unavailable
    /// or the requested algorithms are not supported on the device.
    public static func generateSecureEnclaveKeyPair() throws -> (classical: SecureEnclave.P256.Signing.PrivateKey,
                                                                 pq: SecureEnclave.MLDSA65.PrivateKey) {
        guard SecureEnclave.isAvailable else {
            throw HybridCryptoError.secureEnclaveUnavailable
        }

        let classical: SecureEnclave.P256.Signing.PrivateKey
        do {
            classical = try SecureEnclave.P256.Signing.PrivateKey()
        } catch {
            throw HybridCryptoError.classical(.keyGenerationFailed(error.localizedDescription))
        }

        let pq: SecureEnclave.MLDSA65.PrivateKey
        do {
            pq = try SecureEnclave.MLDSA65.PrivateKey()
        } catch {
            throw HybridCryptoError.postQuantum(.keyGenerationFailed(error.localizedDescription))
        }
        return (classical, pq)
    }

    /// Hybrid sign using Secure Enclave private keys.
    public static func sign(message: Data,
                            classicalKey: SecureEnclave.P256.Signing.PrivateKey,
                            pqKey: SecureEnclave.MLDSA65.PrivateKey,
                            context: Data? = nil) throws -> HybridSignature {
        let pqSig: Data
        do {
            pqSig = try pqKey.signature(for: message, context: context)
        } catch {
            throw HybridCryptoError.postQuantum(.signingFailed(error.localizedDescription))
        }
        guard !pqSig.isEmpty else {
            throw HybridCryptoError.postQuantum(.invalidSignatureFormat)
        }

        let ecSig: Data
        do {
            ecSig = try classicalKey.signature(for: message).rawRepresentation
        } catch {
            throw HybridCryptoError.classical(.signingFailed(error.localizedDescription))
        }
        guard ecSig.count == 64 else {
            throw HybridCryptoError.classical(.invalidSignatureFormat)
        }

        return HybridSignature(
            pqSignature: pqSig,
            classicalSignature: ecSig,
            message: message,
            algorithm: Self.algorithm,
            context: context
        )
    }

    // MARK: - Helpers for public-key construction
    public static func makeClassicalPublic(_ data: Data) throws -> P256.Signing.PublicKey {
        do {
            return try P256.Signing.PublicKey(rawRepresentation: data)
        } catch {
            throw HybridCryptoError.classical(.invalidKeyMaterial)
        }
    }

    public static func makePQPublic(_ data: Data) throws -> MLDSA65.PublicKey {
        do {
            return try MLDSA65.PublicKey(rawRepresentation: data)
        } catch {
            throw HybridCryptoError.postQuantum(.invalidKeyMaterial)
        }
    }
}

// MARK: - Optional Driver Protocol (for HSM / remote backends)
/// Use only when you need a remote HSM. Kept minimal to preserve simplicity.
public protocol CryptoDriver {
    func generateHybridKeyPair() throws -> HybridKeyHandle
    func hybridSign(identifier: String, message: Data, context: Data?) throws -> HybridSignature
    func hybridVerify(classicalPublic: Data, pqPublic: Data, signature: HybridSignature, message: Data, context: Data?) throws -> Bool
    var name: String { get }
}

public enum CryptoDriverError: Error, Equatable {
    case invalidEndpoint
    case backendNotImplemented
    case networkError(String)
    case invalidResponse
    case operationFailed(String)
}

// MARK: - nShield REST Driver
/// Skeleton for Entrust nShield Web Services Option Pack REST API.
/// Expects mutual TLS. Configure the URLSession with the client identity
/// before use. All operations currently demonstrate the request shape;
/// wire the exact JSON fields to your deployed OpenAPI spec.
public final class NShieldRESTDriver: CryptoDriver {
    public let name = "nShield-REST"
    private let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) throws {
        guard baseURL.scheme?.lowercased() == "https",
              let host = baseURL.host, !host.isEmpty,
              baseURL.user == nil, baseURL.password == nil else {
            throw CryptoDriverError.invalidEndpoint
        }
        self.baseURL = baseURL
        self.session = session
    }

    public func generateHybridKeyPair() throws -> HybridKeyHandle {
        // Example: create two keys (ECDSA-P256 + ML-DSA-65) or one hybrid key if the HSM supports it.
        // POST /km/v1/keys  (or the exact path from your openapi.yaml)
        // Body shape depends on the WSOP version; typical fields: type, algorithm, protection domain.
        // On success the response contains a kid and public key material.
        throw HybridCryptoError.driver(.backendNotImplemented)
        /*
        var request = URLRequest(url: baseURL.appendingPathComponent("km/v1/keys"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        // request.httpBody = ... JSON for ML-DSA-65 and/or ECDSA-P256
        // let (data, response) = try await session.data(for: request)
        // parse kid + public keys, return HybridKeyHandle
        */
    }

    public func hybridSign(identifier: String, message: Data, context: Data?) throws -> HybridSignature {
        // POST /crypto/v1/sign
        // Typical body: { "kid": identifier, "alg": "ML-DSA-65", "payload": base64(message), "context": ... }
        // Then a second call (or combined if supported) for the classical signature.
        // Concatenate the two signature values.
        throw HybridCryptoError.driver(.backendNotImplemented)
        /*
        let payload = message.base64EncodedString()
        var request = URLRequest(url: baseURL.appendingPathComponent("crypto/v1/sign"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        // request.httpBody = JSONEncoder().encode([...])
        // Parse "signature" field, base64-decode, build HybridSignature
        */
    }

    public func hybridVerify(classicalPublic: Data, pqPublic: Data,
                             signature: HybridSignature, message: Data, context: Data?) throws -> Bool {
        // POST /crypto/v1/verify
        // Body includes kid or raw public keys, alg, payload, signature.
        // Return the "valid" boolean from the response.
        throw HybridCryptoError.driver(.backendNotImplemented)
    }
}

// MARK: - Implemented local capabilities
public enum SupportedAlgorithms {
    public static let classical = ["ECDSA-P256"]
    public static let postQuantum = ["ML-DSA-65"]
    public static let hybrid = ["ECDSA-P256+ML-DSA-65"]
}
