import Foundation
import Testing
@testable import CryptoSwift

@Suite
struct FastDecryptTests {
    @Test
    func matchesPythonVector() throws {
        // Key is RIPEMD-128("abc") to mirror the Python helper usage.
        let key = RIPEMD128.hash(Data("abc".utf8))
        let ciphertext = Data(hex: "5a2e8f1c9db4c3028f0b")
        let expectedPlaintext = Data(hex: "52f3c6545db56a5e7655")

        let plaintext = try RIPEMD128.fastDecrypt(ciphertext, key: key)
        #expect(plaintext == expectedPlaintext)
    }

    @Test
    func emptyKeyThrows() {
        let ciphertext = Data(hex: "5a2e8f1c9db4c3028f0b")
        #expect(throws: RIPEMD128.FastDecryptError.emptyKey) {
            _ = try RIPEMD128.fastDecrypt(ciphertext, key: Data())
        }
    }
}
