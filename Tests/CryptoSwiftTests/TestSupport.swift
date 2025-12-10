import Foundation

extension Data {
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

    func toHexString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
