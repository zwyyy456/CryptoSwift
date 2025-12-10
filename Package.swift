// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoSwift",
    products: [
        .library(
            name: "CryptoSwift",
            targets: ["CryptoSwift"]
        ),
    ],
    targets: [
        .target(
            name: "CryptoSwift"
        ),
        .testTarget(
            name: "CryptoSwiftTests",
            dependencies: ["CryptoSwift"]
        ),
    ]
)
