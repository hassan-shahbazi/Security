//
//  Asymmetric.swift
//  SecurityWrapper
//
//  Created by Hassan Shahbazi on 2018-06-18.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import Foundation
import Security

public class Asymmetric: NSObject {
    private var keyAlgo:    CFString!
    private var keySize:    NSNumber!
    private var signAlgo:   SecKeyAlgorithm!
    private var encAlgo:    SecKeyAlgorithm!
    private var keyAccess:  CFString!
    
    public init(keyType: CFString = kSecAttrKeyTypeECSECPrimeRandom, keySize: Int = 256, signAlgo: SecKeyAlgorithm = .ecdsaSignatureDigestX962SHA256, encryptionAlgo: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM, keychainAccess: CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
        super.init()
        
        self.keyAlgo = keyType
        self.keySize = NSNumber(value: keySize)
        self.signAlgo = signAlgo
        self.encAlgo = encryptionAlgo
        self.keyAccess = keychainAccess
    }
    
    public func generateKeyPair(publicKeyID: String? = nil, privateKeyID: String? = nil) -> (SecKey?, SecKey?) {
        var publicKey:  SecKey?
        var privateKey: SecKey?
        
        var privateKeyAttribute = [CFString:Any]()
        var publicKeyAttribute  = [CFString:Any]()
        var keyPairAttribute    = [CFString:Any]()
        
        privateKeyAttribute[kSecAttrIsPermanent]    = NSNumber(value: privateKeyID != nil)
        privateKeyAttribute[kSecAttrAccessible]     = keyAccess
        privateKeyAttribute[kSecAttrApplicationTag] = privateKeyID?.data(using: .utf8)
        
        publicKeyAttribute[kSecAttrIsPermanent]     = NSNumber(value: publicKeyID != nil)
        publicKeyAttribute[kSecAttrAccessible]      = keyAccess
        publicKeyAttribute[kSecAttrApplicationTag]  = publicKeyID?.data(using: .utf8)
        
        keyPairAttribute[kSecAttrType]              = keyAlgo
        keyPairAttribute[kSecAttrKeySizeInBits]     = keySize
        keyPairAttribute[kSecPrivateKeyAttrs]       = privateKeyAttribute
        keyPairAttribute[kSecPublicKeyAttrs]        = publicKeyAttribute
        
        SecKeyGeneratePair(keyPairAttribute as CFDictionary, &publicKey, &privateKey)
        return (publicKey, privateKey)
    }
    
    public func getKey(id: String) -> SecKey? {
        return queryKeychain(id, kSecReturnRef) as! SecKey?
    }
    
    public func getKey(id: String) -> Data? {
        return queryKeychain(id, kSecReturnData) as? Data
    }
    
    public func sign(data: Data, privateKeyID: String) throws -> Data?  {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(id: privateKeyID) {
            if SecKeyIsAlgorithmSupported(key, .sign, self.signAlgo) {
                if let signature = SecKeyCreateSignature(key, self.signAlgo, data as CFData, &error) {
                    return signature as Data?
                }
                throw error!.takeRetainedValue() as Error
            }
        }
        return nil
    }
    
    public func verify(rawData: Data, signedData: Data, publicKeyID: String) throws -> Bool {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(id: publicKeyID) {
            if SecKeyIsAlgorithmSupported(key, .verify, self.signAlgo) {
                if SecKeyVerifySignature(key, self.signAlgo, rawData as CFData, signedData as CFData, &error) {
                    return true
                }
                throw error!.takeRetainedValue() as Error
            }
        }
        return false
    }
    
    public func encrypt(text: Data, keyID: String) throws -> Data? {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(id: keyID) {
            if SecKeyIsAlgorithmSupported(key, .encrypt, self.encAlgo) {
                if let cipher = SecKeyCreateEncryptedData(key, self.encAlgo, text as CFData, &error) {
                    return cipher as Data
                }
                throw error!.takeRetainedValue()
            }
        }
        return nil
    }
    
    public func decrypt(cipher: Data, keyID: String) throws -> Data? {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(id: keyID) {
            if SecKeyIsAlgorithmSupported(key, .decrypt, self.encAlgo) {
                if let plain = SecKeyCreateDecryptedData(key, encAlgo, cipher as CFData, &error) {
                    return plain as Data
                }
                throw error!.takeRetainedValue()
            }
        }
        return nil
    }
    
    public func computeSharedSecret(privateKey: String, publicKey: String, algo: SecKeyAlgorithm = .ecdhKeyExchangeStandardX963SHA256, parameters: [String:Any] = [:]) throws -> Data? {
        if let pvKey: SecKey = self.getKey(id: privateKey) {
            if let pubKey: SecKey = self.getKey(id: publicKey) {
                return try computeSharedSecret(pvKey, pubKey, algo, parameters)
            }
        }
        return nil
    }
    
    public func computeSharedSecret(privateKey: Data, publicKey: Data, algo: SecKeyAlgorithm = .ecdhKeyExchangeStandardX963SHA256, parameters: [String:Any] = [:]) throws -> Data? {
        if let pvKey: SecKey = self.dataToSecKey(privateKey: privateKey) {
            if let pubKey: SecKey = self.dataToSecKey(publicKey: publicKey) {
                return try computeSharedSecret(pvKey, pubKey, algo, parameters)
            }
        }
        return nil
    }
}

extension Asymmetric {
    private func computeSharedSecret(_ privateKey: SecKey, _ publicKey: SecKey, _ algo: SecKeyAlgorithm = .ecdhKeyExchangeStandardX963SHA256, _ parameters: [String:Any]) throws -> Data? {
        
        var error: Unmanaged<CFError>?
        if let sharedSecret = SecKeyCopyKeyExchangeResult(privateKey, algo, publicKey, parameters as CFDictionary, &error) {
            return sharedSecret as Data
        }
        throw error!.takeRetainedValue() as Error
    }

    private func queryKeychain(_ id: String, _ type: CFString) -> AnyObject? {
        var keyAttribute  = [CFString:Any]()
        var key:  AnyObject?
        
        keyAttribute[kSecAttrType]            = keyAlgo
        keyAttribute[kSecClass]               = kSecClassKey
        keyAttribute[kSecAttrApplicationTag]  = id.data(using: .utf8)
        keyAttribute[type]                    = NSNumber(value: true)
        keyAttribute[kSecAttrAccessible]      = keyAccess
        
        SecItemCopyMatching(keyAttribute as CFDictionary, &key)
        return key
    }

    private func dataToSecKey(publicKey: Data) -> SecKey? {
        return dataToSecKey(key: publicKey, type: kSecAttrKeyClassPublic)
    }
    
    private func dataToSecKey(privateKey: Data) -> SecKey? {
        return dataToSecKey(key: privateKey, type: kSecAttrKeyClassPrivate)
    }
    
    private func dataToSecKey(key: Data, type: CFString) -> SecKey? {
        var keyAttribute = [CFString:Any]()
        keyAttribute[kSecAttrType] = keyAlgo
        keyAttribute[kSecAttrKeyClass] = type
        
        return SecKeyCreateWithData(key as CFData, keyAttribute as CFDictionary, nil)
    }
}
