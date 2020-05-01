//
//  HASH.swift
//  SignVerify
//
//  Created by Hassan Shahbazi on 2018-05-19.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import UIKit
import CommonCrypto

public enum HashAlgorithm {
    case SHA1
    case SHA224
    case SHA256
    case SHA384
    case SHA512
    case MD5

    var Algorithm: Int {
        switch self {
            case .SHA1:
                return kCCHmacAlgSHA1
            case .SHA224:
                return kCCHmacAlgSHA224
            case .SHA256:
                return kCCHmacAlgSHA256
            case .SHA384:
                return kCCHmacAlgSHA384
            case .SHA512:
                return kCCHmacAlgSHA512
            case .MD5:
                return kCCHmacAlgMD5
        }
    }

    var DigestLength: Int32 {
        switch self {
            case .SHA1:
                return CC_SHA1_DIGEST_LENGTH
            case .SHA224:
                return CC_SHA224_DIGEST_LENGTH
            case .SHA256:
                return CC_SHA256_DIGEST_LENGTH
            case .SHA384:
                return CC_SHA384_DIGEST_LENGTH
            case .SHA512:
                return CC_SHA512_DIGEST_LENGTH
            case .MD5:
                return CC_MD5_DIGEST_LENGTH
        }
    }

    var object: Hash {
        switch self {
            case .SHA1:
                return HashSHA1()
            case .SHA224:
                return HashSHA224()
            case .SHA256:
                return HashSHA256()
            case .SHA384:
                return HashSHA384()
            case .SHA512:
                return HashSHA512()
            case .MD5:
                return HashMD5()
            }
    }
}

public class Hash: NSObject {
    private var algorithm: HashAlgorithm!

    internal override init() {
        super.init()
    }

    public init(_ algorithm: HashAlgorithm) {
        super.init()
        self.algorithm = algorithm
    }

    public func hash(_ message: Data) -> Data? {
        var digestData = Data(count: Int(algorithm.DigestLength))

        _ = digestData.withUnsafeMutableBytes {digestBytes in
            message.withUnsafeBytes { messageBytes in
                algorithm.object.hash(data: messageBytes, len: CC_LONG(message.count), md: digestBytes)
            }
        }
        return digestData
    }

    internal func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {}

    public func hmac(message: Data, key: Data) -> Data? {
        var macData = Data(count: Int(algorithm.DigestLength))

        macData.withUnsafeMutableBytes { macBytes in
            message.withUnsafeBytes { messageBytes in
                key.withUnsafeBytes { keyBytes in
                    CCHmac(CCHmacAlgorithm(algorithm.Algorithm), keyBytes, key.count, messageBytes, message.count, macBytes)
                }
            }
        }
        return macData
    }
}

class HashSHA1: Hash {
    internal override func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {
        CC_SHA1(data, len, md)
    }
}

class HashSHA224: Hash {
    internal override func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {
        CC_SHA224(data, len, md)
    }
}

class HashSHA256: Hash {
    internal override func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {
        CC_SHA256(data, len, md)
    }
}

class HashSHA384: Hash {
    internal override func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {
        CC_SHA384(data, len, md)
    }
}

class HashSHA512: Hash {
    internal override func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {
        CC_SHA512(data, len, md)
    }
}

class HashMD5: Hash {
    internal override func hash(data: UnsafeRawPointer, len: CC_LONG, md: UnsafeMutablePointer<UInt8>) {
        CC_MD5(data, len, md)
    }
}
