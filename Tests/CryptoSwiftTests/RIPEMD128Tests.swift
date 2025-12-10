import Foundation
import Testing
@testable import CryptoSwift

@Suite
struct RIPEMD128Tests {
    @Test
    func referenceVectors() {
        let vectors: [(String, String)] = [
            ("", "cdf26213a150dc3ecb610f18f6b38b46"),
            ("a", "86be7afa339d0fc7cfc785e72f578d33"),
            ("abc", "c14a12199c66e4ba84636b0f69144c77"),
            ("message digest", "9e327b3d6e523062afc1132d7df9d1b8"),
            ("abcdefghijklmnopqrstuvwxyz", "fd2aa607f71dc8f510714922b371834e"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "a1aa0689d0fafa2ddc22e88b49133a06"
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d1e959eb179c911faea4624c60c5c702"
            ),
            (String(repeating: "1234567890", count: 8), "3f45ef194732c2dbb2c4a2c769795fa3"),
            (String(repeating: "a", count: 1_000_000), "4a7f5723f954eba1216c9d8f6320431f"),
        ]

        for (message, expectedHex) in vectors {
            let digest = RIPEMD128.hash(Data(message.utf8))
            #expect(digest.toHexString() == expectedHex)
        }
    }

    @Test
    func littleEndianDigestMatchesPythonScript() {
        let message = Data([0x95, 0x36, 0x00, 0x00, 0x95, 0x36, 0x00, 0x00])
        let digest = RIPEMD128.hash(message)

        let littleEndianHex = "0x" + digest.reversed().map { String(format: "%02x", $0) }.joined()
        #expect(littleEndianHex == "0x65d3fb563a13db28407daf0a4fe5445e")
    }

    @Test
    func digestDataMatchesPythonScriptLiteral() {
        let message = Data([0x95, 0x36, 0x00, 0x00, 0x95, 0x36, 0x00, 0x00])
        let digest = RIPEMD128.hash(message)

        let expected = Data([
            0x5e, 0x44, 0xe5, 0x4f, 0x0a, 0xaf, 0x7d, 0x40,
            0x28, 0xdb, 0x13, 0x3a, 0x56, 0xfb, 0xd3, 0x65,
        ])

        #expect(digest == expected)
    }
}
