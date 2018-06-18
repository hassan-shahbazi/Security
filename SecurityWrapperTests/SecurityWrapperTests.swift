//
//  SecurityWrapperTests.swift
//  SecurityWrapperTests
//
//  Created by Hassan Shahbazi on 2018-05-20.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import XCTest
import Security
@testable import SecurityWrapper

class SecurityWrapperTests: XCTestCase {
    
    let rawData = "t5$A1ZIPdPbyi*)n-9vDJKPfoYW%Ld35VIJ8QBgn$rCUtiRhlqWdx2Pe^O-qL%R&".data(using: .utf8)!
    let plainText = "Hassan Shahbazi".data(using: .utf8)!
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test_1_keyGeneration() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        let (pubKey, pKey) = security.generateKeyPair(publicKeyID: "PublicKeyID", privateKeyID: "PrivateKeyID")
        
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }
    
    func test_2_keyData() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        let pubkey: Data? = security.getKey(id: "PublicKeyID")
        let pkey: Data? = security.getKey(id: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_3_keyRef() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        let pubkey: SecKey? = security.getKey(id: "PublicKeyID")
        let pkey: SecKey? = security.getKey(id: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_4_signData() {
        let security = Security(signAlgo: .ecdsaSignatureDigestX962SHA512, keychainAccess: kSecAttrAccessibleAlways)
        do {
            let sign = try security.sign(data: rawData, privateKeyID: "PrivateKeyID")
            XCTAssertNotNil(sign)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_5_verifySign() {
        let security = Security(signAlgo: .ecdsaSignatureDigestX962SHA512, keychainAccess: kSecAttrAccessibleAlways)
        do {
            let sign = try security.sign(data: rawData, privateKeyID: "PrivateKeyID")
            XCTAssertNotNil(sign)
            
            let verify = try security.verify(rawData: rawData, signedData: sign!, publicKeyID: "PublicKeyID")
            XCTAssertTrue(verify)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_6_encrypt() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        do {
            let cipher = try security.encrypt(text: plainText, keyID: "PublicKeyID")
            
            XCTAssertNotNil(cipher)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_7_decrypt() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        do {
            let cipher = try security.encrypt(text: plainText, keyID: "PublicKeyID")
            XCTAssertNotNil(cipher)
            
            let plain = try security.decrypt(cipher: cipher!, keyID: "PrivateKeyID")
            XCTAssertNotNil(plain)
            XCTAssertEqual(plain, plainText)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }

    func test_8_generateKeyPairWithoutSaving() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        let (pubKey, pKey) = security.generateKeyPair()
    
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }

    func test_9_calculateShareSecrets_ID() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        let _ = security.generateKeyPair(publicKeyID: "PubKeyID1", privateKeyID: "PvKeyID1")
        let _ = security.generateKeyPair(publicKeyID: "PubKeyID2", privateKeyID: "PvKeyID2")
        
        let sharedSecret1 = try? security.calculateSharedSecret(privateKey: "PvKeyID1", publicKey: "PubKeyID2")
        let sharedSecret2 = try? security.calculateSharedSecret(privateKey: "PvKeyID2", publicKey: "PubKeyID1")
        
        XCTAssertNotNil(sharedSecret1 as Any)
        XCTAssertNotNil(sharedSecret2 as Any)
        XCTAssertEqual(sharedSecret1, sharedSecret2)
        
        let wrongSharedSecret = try? security.calculateSharedSecret(privateKey: "PvKeyID2", publicKey: "PublicKeyID")
        XCTAssertNotEqual(sharedSecret1, wrongSharedSecret)
    }
    
    func test_10_calculateShareSecrets_Data() {
        let security = Security(keychainAccess: kSecAttrAccessibleAlways)
        
        let pubKey1Data: Data = security.getKey(id: "PubKeyID1")!
        let pubKey2Data: Data = security.getKey(id: "PubKeyID2")!
        let pvKey1Data: Data = security.getKey(id: "PvKeyID1")!
        let pvKey2Data: Data = security.getKey(id: "PvKeyID2")!
        
        let sharedSecret1 = try? security.calculateSharedSecret(privateKey: pvKey1Data, publicKey: pubKey2Data)
        let sharedSecret2 = try? security.calculateSharedSecret(privateKey: pvKey2Data, publicKey: pubKey1Data)
        
        XCTAssertNotNil(sharedSecret1 as Any)
        XCTAssertNotNil(sharedSecret2 as Any)
        XCTAssertEqual(sharedSecret1, sharedSecret2)
        
        let pubKeyWrongData: Data = security.getKey(id: "PublicKeyID")!
        let wrongSharedSecret = try? security.calculateSharedSecret(privateKey: pvKey2Data, publicKey: pubKeyWrongData)
        XCTAssertNotEqual(sharedSecret1, wrongSharedSecret)
    }
}

extension Data {
    public var bytes: [UInt8] {
        return [UInt8](self)
    }
    
    public var hex: String {
        var str = ""
        for byte in self.bytes {
            str = str.appendingFormat("%02x", UInt(byte))
        }
        return str
    }
}
