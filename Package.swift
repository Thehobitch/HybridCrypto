// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HybridCrypto",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
        .macCatalyst(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
        .visionOS(.v26)
    ],
    products: [
        .library(
            name: "HybridCrypto",
            targets: ["HybridCrypto"]
        )
    ],
    targets: [
        .target(
            name: "HybridCrypto"
        ),
        .testTarget(
            name: "HybridCryptoTests",
            dependencies: ["HybridCrypto"]
        )
    ]
)
