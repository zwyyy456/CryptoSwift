import XCTest
@testable import Salsa20Swift

final class Salsa20SwiftTests: XCTestCase {
    func testFirstBlockMatchesReferenceVector() throws {
        let key = Data((0..<32).map(UInt8.init))
        let nonce = Data(repeating: 0, count: 8)
        let cipher = try Salsa20Cipher(key: key, nonce: nonce)

        let result = cipher.process(Data(repeating: 0, count: 64))
        let expected = Data(hex: "b580f7671c76e5f7441af87c146d6b513910dc8b4146ef1b3211cf12af4a4b49e5c874b3ef4f85e7d7ed539ffeba73eb73e0cca74fbd306d8aa716c7783e89af")

        XCTAssertEqual(result, expected)
    }

    func testTwoBlocksMatchReferenceVector() throws {
        let key = Data((0..<32).map(UInt8.init))
        let nonce = Data(repeating: 0, count: 8)
        let cipher = try Salsa20Cipher(key: key, nonce: nonce)

        let result = cipher.process(Data(repeating: 0, count: 128))
        let expected = Data(hex:
            "b580f7671c76e5f7441af87c146d6b513910dc8b4146ef1b3211cf12af4a4b49e5c874b3ef4f85e7d7ed539ffeba73eb73e0cca74fbd306d8aa716c7783e89af" +
            "e080f82977fd81f5d5a858048c299a4eaedd2835a3b30cc6e3870cddf7387f6f60e50747c118e3d38b7e8751db02da647bde67dd2efa847b575e8e72a4afe8c8"
        )

        XCTAssertEqual(result, expected)
    }

    func testSalsa20_128Vectors() throws {
        let key = Data((0..<16).map(UInt8.init)) // 128-bit
        let nonce = Data(repeating: 0, count: 8)
        let cipher = try Salsa20Cipher(key: key, nonce: nonce)

        let result = cipher.process(Data(repeating: 0, count: 128))
        let expected = Data(hex:
            "2dd5c3f7ba2b20f76802410c688688895ad8c1bd4ea6c9b140fb9b90e21049bf583f527970ebc1a4c4c5af117a5940d92b98895b1902f02bf6e9bef8d6b4ccbe" +
            "ae17cc187c9b8260f46a62d440c845970d9dad1edb8d8575dcae006acdf6af2f1373dff1263a06b3d063f46d6f5e6e013759021419d29db03a992b2fd1c6a0cb"
        )

        XCTAssertEqual(result, expected)
    }

    func testEncryptDecryptRoundTrip() throws {
        let key = Data(Array(0...31).map(UInt8.init))
        let nonce = Data(Array(1...8).map(UInt8.init))
        let cipher = try Salsa20Cipher(key: key, nonce: nonce, counter: 5) // non-zero counter

        let message = Data("The quick brown fox jumps over the lazy dog".utf8)
        let encrypted = cipher.process(message)

        let decryptCipher = try Salsa20Cipher(key: key, nonce: nonce, counter: 5)
        let decrypted = decryptCipher.process(encrypted)

        XCTAssertEqual(decrypted, message)
    }

    func testInvalidRoundsThrows() {
        let key = Data(repeating: 0, count: 32)
        let nonce = Data(repeating: 0, count: 8)
        XCTAssertThrowsError(try Salsa20Cipher(key: key, nonce: nonce, rounds: 7))
        XCTAssertThrowsError(try Salsa20Cipher(key: key, nonce: nonce, rounds: 0))
    }
}

// MARK: - Test helpers

private extension Data {
    init(hex: String) {
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            let byteString = hex[index..<nextIndex]
            let byte = UInt8(byteString, radix: 16)!
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
