//
//  Symmetric.swift
//  SecurityWrapper
//
//  Created by Hassan Shahbazi on 2018-06-18.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import UIKit
import Security
import CommonCrypto

public class Symmetric: NSObject {
    private var encAlgo:    Int!
    private var paddingAlgo: Int!
    private var blockSize: Int!
    private var keySize: Int!
    private var keyAccess:  CFString!

    public init (encryptionAlgo: Int = kCCAlgorithmAES, paddingAlgo: Int = kCCOptionPKCS7Padding, blockSize: Int = kCCBlockSizeAES128, keySize: Int = kCCKeySizeAES128, keychainAccess: CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
        super.init()
        
        self.encAlgo = encryptionAlgo
        self.paddingAlgo = paddingAlgo
        self.blockSize = blockSize
        self.keySize = keySize
        self.keyAccess = keychainAccess
    }
    
    public func generateSymmetricKey(id: String? = nil) -> Data? {
        var keyData = Data(count: self.keySize)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, self.keySize, $0)
        }
        if result == errSecSuccess {
            if let id = id {
                Keychain.saveKey(token: keyData.base64EncodedString(), id: id)
            }
            return keyData
        }
        return nil
    }
    
    public func getKey(id: String) -> Data? {
        return Data(base64Encoded: Keychain.loadKey(id: id) ?? "")
    }
    
    public func encrypt(plain: Data, key: Data, iv: Data) -> Data? {
        return self.crypt(data: plain, key: key, iv: iv, operation: kCCEncrypt)
    }
    
    public func decrypt(cipher: Data, key: Data, iv: Data) -> Data? {
        return self.crypt(data: cipher, key: key, iv: iv, operation: kCCDecrypt)
    }
}

extension Symmetric {
    private func crypt(data: Data, key: Data, iv: Data, operation:Int) -> Data? {
        let cryptLength = size_t(data.count + self.blockSize)
        var cryptData = Data(count:cryptLength)
        
        let keyLength = size_t(self.keySize)
        let options = CCOptions(self.paddingAlgo)
        
        var numBytesEncrypted :size_t = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                iv.withUnsafeBytes {ivBytes in
                    key.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(operation),
                                CCAlgorithm(self.encAlgo),
                                options,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, data.count,
                                cryptBytes, cryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
            return cryptData
        }
        return nil
    }
}
