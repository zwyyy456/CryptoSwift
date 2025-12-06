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

    func testLongStreamMatchesPythonReference() throws {
        // Mirrors the Python test_salsa20() parity check against PyCryptodome,
        // using a deterministic key/nonce/plaintext and a 1000-byte keystream span.
        let key = Data((0..<32).map(UInt8.init))
        let nonce = Data((0..<8).map(UInt8.init))
        let plaintext = Data((0..<1000).map { UInt8($0 % 256) })

        let cipher = try Salsa20Cipher(key: key, nonce: nonce)
        let ciphertext = cipher.process(plaintext)

        let expectedCiphertext = Data(hex:
            "2eac0d5c1c522fc9de7bb9a224e95af83fca56bb6f89cec501fdf60fb2e4d8a3579e275c727cf1521061d2f8d25bb28a" +
            "cde9374e72075fa7ddc80cd9c08a8543e17b691a9d413dcaf6f0748ffbc1afeacb934237474d9a9931146aa4dd8ff1b8" +
            "dd94c1b6e8d19fc3853b2de952790fe076ad13bc90cd94cdfb1ef9c9fc9293b507c13d6456ba1a83ba4bd38810f4d9b5" +
            "32b152e1bf9100b46b3804074d2cdd6d63cdb85f70bc81a8ce69d2315a04de829d1554c557601bfdda9af5084979540c" +
            "4088af8e1716ee08f9a3db19f97848b42cbf0dc123f8c92e812028272de226981ddf08607ff0075767c2a6b666f67d8a" +
            "d7311cc6580da609d39d9ffaa69ee1802741bd04a7e16fad2fd9020a8ed9266e280ff1e05f9761dc1101af68ed1f3cad" +
            "c1fb8d6659b607a3069c3e46a31980e609c903863052606395722988cfcc6aa6636a3a9d1635437f5211e693b03c2001" +
            "d06144228fe32a3e32ad784f6dd6319feaf8455d80e66520f9bf6325e7091e83a686bbcaca40c73381416ff1fc83ff45" +
            "cf1b842fef59226468c58542d1aa78783bf7e9db41f9b44a3755723dee50417bbb99220d35e4d74b8945203c99adbcac" +
            "b99ff1bab597780a912652887196cb18564969168eebaefbe02a0315f0984fc9f7f4fdeaf07b62be19b2a9eeb1a7538c" +
            "f01d5cea7921bc3d04caffa3e68f51c16b3a5bb08f19524ee43eb126882d529d1c3cd9b7a22c2f57efd35b091fafad89" +
            "1158f111fb38da9ca5c388b5789af7775c74ea0996eccb20c1e91c9a5ae867022f23d6bc0eed3aef5c782fffeab85a29" +
            "0ea9daec3a5d4db840aca47895fc3dfed9ef74d316a3839ce4ad69f631b3f222b371196981f54496b85adb3790472724" +
            "328a87940a948eac2a6789482c4d19fe3baeb864e3c6d7c4ea2f646915e7a8d3af9126a02cbab33d1e828e85cc57c070" +
            "816d7ea8a54ccbd1d6ae1fcfe16a8df0dd874d5a41331e2b0f0d3eaf62cdc1e1db69b7aad5832f625190ec80401cbb38" +
            "3158428817fddafb8ae4c604ed765bdeedac0a0eb85b64ca42a9cb6226c601461aed16f1e454ea6a17804877d20e7ee8" +
            "f488a71c6b33386609e0220948b502911b38b2dac4d1662ece78c0ddb45fd95bb1253c62dcee6ac00e5bd1df66036699" +
            "d5cb8a427c594403488755b498337a25aa9c9b9d1ed3bb3d3c9d2a0aa974511d7e9d967ceceed0fda03369369d80b3d1" +
            "8ec394ce7a5bdb39c9db97c9b7cf65641f010860f5e307cbd51e9c5804ace3842d7b43f0b19015698b0a9f74debefbef" +
            "a69308991d71c36c501071727eb55a91d7d8985e51060081d00a5e584d594a5c94e8e669567964972391f7980092ad48" +
            "d52304f1f9d827740d3a2f3fcf8e6022b3d0dc7f070badcd86227684753a6e4759298c11409161be"
        )

        XCTAssertEqual(ciphertext, expectedCiphertext)
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
