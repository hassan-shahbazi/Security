//
//  Security.swift
//  SignVerify
//
//  Created by Hassan Shahbazi on 2018-03-27.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import UIKit
import Security

class Security: NSObject {
    
    private var keyAlgo:    CFString!
    private var keySize:    NSNumber!
    private var signAlgo:   SecKeyAlgorithm!
    private var keyAccess:  CFString!
    
    init(KeyType:           CFString = kSecAttrKeyTypeEC,
         KeySize:           Int = 256,
         SignAlgorithm:     SecKeyAlgorithm = .ecdsaSignatureDigestX962SHA256,
         KeycahinAccess:    CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
        
        super.init()
        keyAlgo     = KeyType
        keySize     = NSNumber(value: KeySize)
        signAlgo    = SignAlgorithm
        keyAccess   = KeycahinAccess
    }
    
    func generateKeyPair(PublicKeyID pubkey: String, PrivateKeyID pkey: String) -> (SecKey?, SecKey?) {
        var publicKey:  SecKey?
        var privateKey: SecKey?
        
        var privateKeyAttribute = [CFString:Any]()
        var publicKeyAttribute  = [CFString:Any]()
        var keyPairAttribute    = [CFString:Any]()

        privateKeyAttribute[kSecAttrIsPermanent]    = NSNumber(value: true)
        privateKeyAttribute[kSecAttrAccessible]     = keyAccess
        privateKeyAttribute[kSecAttrApplicationTag] = pkey.data(using: .utf8)
        
        publicKeyAttribute[kSecAttrIsPermanent]     = NSNumber(value: true)
        publicKeyAttribute[kSecAttrAccessible]      = keyAccess
        publicKeyAttribute[kSecAttrApplicationTag]  = pubkey.data(using: .utf8)

        keyPairAttribute[kSecAttrType]              = keyAlgo
        keyPairAttribute[kSecAttrKeySizeInBits]     = keySize
        keyPairAttribute[kSecPrivateKeyAttrs]       = privateKeyAttribute
        keyPairAttribute[kSecPublicKeyAttrs]        = publicKeyAttribute
        
        SecKeyGeneratePair(keyPairAttribute as CFDictionary, &publicKey, &privateKey)
        return (publicKey, privateKey)
    }
    
    func getKey(ID id: String) -> SecKey? {
        return queryKeychain(ID: id, Type: kSecReturnRef) as! SecKey?
    }
    
    func getKey(ID id: String) -> Data? {
        return queryKeychain(ID: id, Type: kSecReturnData) as? Data
    }
    
    func checkSignVerifySupport(Key id: String) -> Bool {
        if let key: SecKey = getKey(ID: id) {
            return SecKeyIsAlgorithmSupported(key, .sign, signAlgo)
        }
        return false
    }
    
    func sign(Data data: Data, PrivateKey pkey: String) throws -> Data?  {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(ID: pkey) {
            if let signature = SecKeyCreateSignature(key, signAlgo, data as CFData, &error) {
                return signature as Data?
            }
            throw error!.takeRetainedValue() as Error
        }
        return nil
    }

    func verify(RawData raw: Data, SignedData data: Data, PublicKey pubkey: String) throws -> Bool {
        var error: Unmanaged<CFError>?
        if let key: SecKey = getKey(ID: pubkey) {
            if SecKeyVerifySignature(key, signAlgo, raw as CFData, data as CFData, &error) {
                return true
            }
            throw error!.takeRetainedValue() as Error
        }
        return false
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
