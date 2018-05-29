//
//  Security.swift
//  SignVerify
//
//  Created by Hassan Shahbazi on 2018-03-27.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import UIKit
import Security

public class Security: NSObject {
    
    private var keyAlgo:    CFString!
    private var keySize:    NSNumber!
    private var signAlgo:   SecKeyAlgorithm!
    private var encAlgo:    SecKeyAlgorithm!
    private var keyAccess:  CFString!
    
    public init(KeyType:           CFString = kSecAttrKeyTypeEC,
                KeySize:           Int = 256,
                SignAlgorithm:     SecKeyAlgorithm = .ecdsaSignatureDigestX962SHA256,
                EncryptAlgorithm:  SecKeyAlgorithm = .eciesEncryptionStandardX963SHA256AESGCM,
                KeycahinAccess:    CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
        
        super.init()
        keyAlgo     = KeyType
        keySize     = NSNumber(value: KeySize)
        signAlgo    = SignAlgorithm
        encAlgo     = EncryptAlgorithm
        keyAccess   = KeycahinAccess
    }
    
    public func generateKeyPair(PublicKeyID pubkey: String? = nil, PrivateKeyID pkey: String? = nil) -> (SecKey?, SecKey?) {
        var publicKey:  SecKey?
        var privateKey: SecKey?
        
        var privateKeyAttribute = [CFString:Any]()
        var publicKeyAttribute  = [CFString:Any]()
        var keyPairAttribute    = [CFString:Any]()

        privateKeyAttribute[kSecAttrIsPermanent]    = NSNumber(value: pubkey != nil)
        privateKeyAttribute[kSecAttrAccessible]     = keyAccess
        privateKeyAttribute[kSecAttrApplicationTag] = pkey?.data(using: .utf8)
        
        publicKeyAttribute[kSecAttrIsPermanent]     = NSNumber(value: pubkey != nil)
        publicKeyAttribute[kSecAttrAccessible]      = keyAccess
        publicKeyAttribute[kSecAttrApplicationTag]  = pubkey?.data(using: .utf8)

        keyPairAttribute[kSecAttrType]              = keyAlgo
        keyPairAttribute[kSecAttrKeySizeInBits]     = keySize
        keyPairAttribute[kSecPrivateKeyAttrs]       = privateKeyAttribute
        keyPairAttribute[kSecPublicKeyAttrs]        = publicKeyAttribute
        
        SecKeyGeneratePair(keyPairAttribute as CFDictionary, &publicKey, &privateKey)
        return (publicKey, privateKey)
    }
    
    public func getKey(ID id: String) -> SecKey? {
        return queryKeychain(ID: id, Type: kSecReturnRef) as! SecKey?
    }
    
    public func getKey(ID id: String) -> Data? {
        return queryKeychain(ID: id, Type: kSecReturnData) as? Data
    }
    
    public func sign(Data data: Data, PrivateKey pkey: String) throws -> Data?  {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(ID: pkey) {
            if SecKeyIsAlgorithmSupported(key, .sign, signAlgo) {
                if let signature = SecKeyCreateSignature(key, signAlgo, data as CFData, &error) {
                    return signature as Data?
                }
                throw error!.takeRetainedValue() as Error
            }
        }
        return nil
    }

    public func verify(RawData raw: Data, SignedData data: Data, PublicKey pubkey: String) throws -> Bool {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(ID: pubkey) {
            if SecKeyIsAlgorithmSupported(key, .verify, signAlgo) {
                if SecKeyVerifySignature(key, signAlgo, raw as CFData, data as CFData, &error) {
                    return true
                }
                throw error!.takeRetainedValue() as Error
            }
        }
        return false
    }

    public func encrypt(Plain text: Data, Key key: String) throws -> Data? {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(ID: key) {
            if SecKeyIsAlgorithmSupported(key, .encrypt, encAlgo) {
                if let cipher = SecKeyCreateEncryptedData(key, encAlgo, text as CFData, &error) {
                    return cipher as Data
                }
                throw error!.takeRetainedValue()
            }
        }
        return nil
    }
    
    public func decrypt(Cipher text: Data, Key key: String) throws -> Data? {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(ID: key) {
            if SecKeyIsAlgorithmSupported(key, .decrypt, encAlgo) {
                if let plain = SecKeyCreateDecryptedData(key, encAlgo, text as CFData, &error) {
                    return plain as Data
                }
                throw error!.takeRetainedValue()
            }
        }
        return nil
    }
}


extension Security {
    private func queryKeychain(ID id: String, Type type: CFString) -> AnyObject? {
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
}
