import XCTest
@testable import HybridCrypto

@available(iOS 26.0, macOS 26.0, macCatalyst 26.0, tvOS 26.0, watchOS 26.0, visionOS 26.0, *)
final class HybridCryptoTests: XCTestCase {
    func testLocalKeyGenerationAndSignVerify() throws {
        let (ecKey, pqKey) = try HybridCrypto.generateKeyPair()
        let message = Data("payload".utf8)
        let context = Data("test-context".utf8)

        let signature = try HybridCrypto.sign(
            message: message,
            classicalKey: ecKey,
            pqKey: pqKey,
            context: context
        )

        let valid = try HybridCrypto.verify(
            signature,
            message: message,
            classicalPublic: ecKey.publicKey,
            pqPublic: pqKey.publicKey,
            context: context
        )
        XCTAssertTrue(valid)
    }

    func testAlgorithmMismatch() throws {
        let (ecKey, pqKey) = try HybridCrypto.generateKeyPair()
        let message = Data("payload".utf8)
        var signature = try HybridCrypto.sign(message: message, classicalKey: ecKey, pqKey: pqKey)
        // Force algorithm mismatch by reconstructing (in real use this would be tampering)
        signature = HybridSignature(
            pqSignature: signature.pqSignature,
            classicalSignature: signature.classicalSignature,
            message: message,
            algorithm: "wrong",
            context: nil
        )

        XCTAssertThrowsError(
            try HybridCrypto.verify(
                signature,
                message: message,
                classicalPublic: ecKey.publicKey,
                pqPublic: pqKey.publicKey
            )
        ) { error in
            guard case HybridCryptoError.hybrid(.algorithmMismatch) = error else {
                XCTFail("Expected algorithmMismatch, got \(error)")
                return
            }
        }
    }
}
