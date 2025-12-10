//  Standalone Salsa20 implementation
//  Adapted from the reference implementation by D. J. Bernstein (public domain).
//
//  Supports custom round counts (default is 20). Key size can be 16 bytes
//  (Salsa20/128) or 32 bytes (Salsa20/256) and nonce is 8 bytes. Encryption and
//  decryption are the same operation (xor with the keystream).

import Foundation

public enum Salsa20Error: Error {
    case invalidKeySize
    case invalidNonceSize
    case invalidRounds
}

public final class Salsa20Cipher {
    private static let sigma: [UInt32] = [
        0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,  // "expand 32-byte k"
    ]
    private static let tau: [UInt32] = [
        0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574,  // "expand 16-byte k"
    ]

    private let keyWords: [UInt32] // always 8 words
    private let nonceWords: [UInt32]
    private var counter: UInt64
    private let rounds: Int
    private let constants: [UInt32] // sigma or tau

    /// - Parameters:
    ///   - key: 16-byte (Salsa20/128) or 32-byte (Salsa20/256) key.
    ///   - nonce: 8-byte nonce (aka IV).
    ///   - counter: initial block counter (defaults to 0).
    ///   - rounds: number of Salsa20 rounds (must be positive and even, defaults to 20).
    public init(key: Data, nonce: Data, counter: UInt64 = 0, rounds: Int = 20) throws {
        guard key.count == 16 || key.count == 32 else { throw Salsa20Error.invalidKeySize }
        guard nonce.count == 8 else { throw Salsa20Error.invalidNonceSize }
        guard rounds > 0 && rounds % 2 == 0 else { throw Salsa20Error.invalidRounds }

        if key.count == 32 {
            self.keyWords = stride(from: 0, to: 32, by: 4).map {
                Salsa20Cipher.le(.init(key[$0..<$0 + 4]))
            }
            self.constants = Self.sigma
        } else {
            var words = [UInt32]()
            for chunkStart in stride(from: 0, to: 16, by: 4) {
                words.append(Salsa20Cipher.le(.init(key[chunkStart..<chunkStart + 4])))
            }
            self.keyWords = words + words // repeat for 128-bit key
            self.constants = Self.tau
        }
        self.nonceWords = stride(from: 0, to: 8, by: 4).map {
            Salsa20Cipher.le(.init(nonce[$0..<$0 + 4]))
        }
        self.counter = counter
        self.rounds = rounds
    }

    /// Encrypts/decrypts the input and advances the internal counter.
    public func process(_ input: Data) -> Data {
        var output = input
        var keystream = [UInt8](repeating: 0, count: 64)

        // Make a mutable copy size to avoid exclusivity issues during withUnsafeMutableBytes.
        let outCount = output.count
        var blockCounter = counter
        var offset = 0

        output.withUnsafeMutableBytes { outPtrRaw in
            guard let outPtr = outPtrRaw.bindMemory(to: UInt8.self).baseAddress else { return }

            while offset < outCount {
                generateKeystreamBlock(counter: blockCounter, into: &keystream)
                let blockEnd = min(offset + 64, outCount)
                let blockLen = blockEnd - offset

                for i in 0..<blockLen {
                    outPtr[offset + i] ^= keystream[i]
                }

                offset = blockEnd
                blockCounter &+= 1
            }
        }

        counter = blockCounter
        return output
    }

    /// Resets the internal counter to a specific block index.
    public func seek(to counter: UInt64) {
        self.counter = counter
    }

    // MARK: - Core

    private func generateKeystreamBlock(counter: UInt64, into buffer: inout [UInt8]) {
        precondition(buffer.count >= 64)

        var state = [UInt32](repeating: 0, count: 16)

        state[0] = constants[0]
        state[1] = keyWords[0]
        state[2] = keyWords[1]
        state[3] = keyWords[2]
        state[4] = keyWords[3]
        state[5] = constants[1]
        state[6] = nonceWords[0]
        state[7] = nonceWords[1]
        state[8] = UInt32(truncatingIfNeeded: counter & 0xffff_ffff)
        state[9] = UInt32(truncatingIfNeeded: counter >> 32)
        state[10] = constants[2]
        state[11] = keyWords[4]
        state[12] = keyWords[5]
        state[13] = keyWords[6]
        state[14] = keyWords[7]
        state[15] = constants[3]

        var working = state
        for _ in stride(from: rounds, to: 0, by: -2) {
            // Column rounds
            working[4] ^= Self.rotl(working[0] &+ working[12], 7)
            working[8] ^= Self.rotl(working[4] &+ working[0], 9)
            working[12] ^= Self.rotl(working[8] &+ working[4], 13)
            working[0] ^= Self.rotl(working[12] &+ working[8], 18)

            working[9] ^= Self.rotl(working[5] &+ working[1], 7)
            working[13] ^= Self.rotl(working[9] &+ working[5], 9)
            working[1] ^= Self.rotl(working[13] &+ working[9], 13)
            working[5] ^= Self.rotl(working[1] &+ working[13], 18)

            working[14] ^= Self.rotl(working[10] &+ working[6], 7)
            working[2] ^= Self.rotl(working[14] &+ working[10], 9)
            working[6] ^= Self.rotl(working[2] &+ working[14], 13)
            working[10] ^= Self.rotl(working[6] &+ working[2], 18)

            working[3] ^= Self.rotl(working[15] &+ working[11], 7)
            working[7] ^= Self.rotl(working[3] &+ working[15], 9)
            working[11] ^= Self.rotl(working[7] &+ working[3], 13)
            working[15] ^= Self.rotl(working[11] &+ working[7], 18)

            // Row rounds
            working[1] ^= Self.rotl(working[0] &+ working[3], 7)
            working[2] ^= Self.rotl(working[1] &+ working[0], 9)
            working[3] ^= Self.rotl(working[2] &+ working[1], 13)
            working[0] ^= Self.rotl(working[3] &+ working[2], 18)

            working[6] ^= Self.rotl(working[5] &+ working[4], 7)
            working[7] ^= Self.rotl(working[6] &+ working[5], 9)
            working[4] ^= Self.rotl(working[7] &+ working[6], 13)
            working[5] ^= Self.rotl(working[4] &+ working[7], 18)

            working[11] ^= Self.rotl(working[10] &+ working[9], 7)
            working[8] ^= Self.rotl(working[11] &+ working[10], 9)
            working[9] ^= Self.rotl(working[8] &+ working[11], 13)
            working[10] ^= Self.rotl(working[9] &+ working[8], 18)

            working[12] ^= Self.rotl(working[15] &+ working[14], 7)
            working[13] ^= Self.rotl(working[12] &+ working[15], 9)
            working[14] ^= Self.rotl(working[13] &+ working[12], 13)
            working[15] ^= Self.rotl(working[14] &+ working[13], 18)
        }

        for i in 0..<16 {
            let word = working[i] &+ state[i]
            let base = i * 4
            buffer[base + 0] = UInt8(truncatingIfNeeded: word)
            buffer[base + 1] = UInt8(truncatingIfNeeded: word >> 8)
            buffer[base + 2] = UInt8(truncatingIfNeeded: word >> 16)
            buffer[base + 3] = UInt8(truncatingIfNeeded: word >> 24)
        }
    }

    // MARK: - Helpers

    private static func rotl(_ value: UInt32, _ bits: UInt32) -> UInt32 {
        (value << bits) | (value >> (32 - bits))
    }

    private static func le(_ bytes: [UInt8]) -> UInt32 {
        UInt32(bytes[0])
            | (UInt32(bytes[1]) << 8)
            | (UInt32(bytes[2]) << 16)
            | (UInt32(bytes[3]) << 24)
    }

    private static func toBytes(_ word: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: word),
            UInt8(truncatingIfNeeded: word >> 8),
            UInt8(truncatingIfNeeded: word >> 16),
            UInt8(truncatingIfNeeded: word >> 24),
        ]
    }
}
