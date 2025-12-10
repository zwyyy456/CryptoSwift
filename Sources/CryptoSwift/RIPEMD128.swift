import Foundation

/// RIPEMD-128 hash implementation (little-endian output).
public struct RIPEMD128 {
    public static func hash(_ data: Data) -> Data {
        var hasher = Hasher()
        hasher.update(data)
        return hasher.finalize()
    }

    // Simple one-shot hasher; expand if streaming is ever needed.
    private struct Hasher {
        private var h0: UInt32 = 0x6745_2301
        private var h1: UInt32 = 0xefcd_ab89
        private var h2: UInt32 = 0x98ba_dcfe
        private var h3: UInt32 = 0x1032_5476

        mutating func update(_ data: Data) {
            var buffer = data
            let bitLength = UInt64(buffer.count) * 8

            buffer.append(0x80)
            while buffer.count % 64 != 56 { buffer.append(0) }

            var lengthLE = bitLength.littleEndian
            withUnsafeBytes(of: &lengthLE) { buffer.append(contentsOf: $0) }

            for offset in stride(from: 0, to: buffer.count, by: 64) {
                var words = [UInt32](repeating: 0, count: 16)
                for i in 0..<16 {
                    let base = offset + (i * 4)
                    words[i] = UInt32(buffer[base])
                        | (UInt32(buffer[base + 1]) << 8)
                        | (UInt32(buffer[base + 2]) << 16)
                        | (UInt32(buffer[base + 3]) << 24)
                }
                compress(words)
            }
        }

        mutating func finalize() -> Data {
            var digest = Data(capacity: 16)
            for word in [h0, h1, h2, h3] {
                var le = word.littleEndian
                withUnsafeBytes(of: &le) { digest.append(contentsOf: $0) }
            }
            return digest
        }

        private mutating func compress(_ x: [UInt32]) {
            var a1 = h0, b1 = h1, c1 = h2, d1 = h3
            var a2 = h0, b2 = h1, c2 = h2, d2 = h3

            for j in 0..<64 {
                let t1 = Self.rotl(a1 &+ fLeft(j, b1, c1, d1) &+ x[Self.r1[j]] &+ kLeft(j), Self.s1[j])
                a1 = d1; d1 = c1; c1 = b1; b1 = t1

                let t2 = Self.rotl(a2 &+ fRight(j, b2, c2, d2) &+ x[Self.r2[j]] &+ kRight(j), Self.s2[j])
                a2 = d2; d2 = c2; c2 = b2; b2 = t2
            }

            let t = h1 &+ c1 &+ d2
            h1 = h2 &+ d1 &+ a2
            h2 = h3 &+ a1 &+ b2
            h3 = h0 &+ b1 &+ c2
            h0 = t
        }

        private func fLeft(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            switch j {
            case 0..<16: return x ^ y ^ z
            case 16..<32: return (x & y) | (~x & z)
            case 32..<48: return (x | ~y) ^ z
            default: return (x & z) | (y & ~z)
            }
        }

        private func fRight(_ j: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
            switch j {
            case 0..<16: return (x & z) | (y & ~z)
            case 16..<32: return (x | ~y) ^ z
            case 32..<48: return (x & y) | (~x & z)
            default: return x ^ y ^ z
            }
        }

        private func kLeft(_ j: Int) -> UInt32 {
            switch j {
            case 0..<16: return 0x0000_0000
            case 16..<32: return 0x5a82_7999
            case 32..<48: return 0x6ed9_eba1
            default: return 0x8f1b_bcdc
            }
        }

        private func kRight(_ j: Int) -> UInt32 {
            switch j {
            case 0..<16: return 0x50a2_8be6
            case 16..<32: return 0x5c4d_d124
            case 32..<48: return 0x6d70_3ef3
            default: return 0x0000_0000
            }
        }

        private static func rotl(_ value: UInt32, _ bits: UInt32) -> UInt32 {
            (value << bits) | (value >> (32 - bits))
        }

        private static let r1: [Int] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        ]

        private static let r2: [Int] = [
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        ]

        private static let s1: [UInt32] = [
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        ]

        private static let s2: [UInt32] = [
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        ]
    }
}
