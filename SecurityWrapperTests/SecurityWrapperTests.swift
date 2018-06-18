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
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        let (pubKey, pKey) = security.generateKeyPair(PublicKeyID: "PublicKeyID", PrivateKeyID: "PrivateKeyID")
        
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }
    
    func test_2_keyData() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        let pubkey: Data? = security.getKey(ID: "PublicKeyID")
        let pkey: Data? = security.getKey(ID: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_3_keyRef() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        let pubkey: SecKey? = security.getKey(ID: "PublicKeyID")
        let pkey: SecKey? = security.getKey(ID: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_4_signData() {
        let security = Security(SignAlgorithm: .ecdsaSignatureDigestX962SHA512, KeycahinAccess: kSecAttrAccessibleAlways)
        do {
            let sign = try security.sign(Data: rawData, PrivateKey: "PrivateKeyID")
            XCTAssertNotNil(sign)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_5_verifySign() {
        let security = Security(SignAlgorithm: .ecdsaSignatureDigestX962SHA512, KeycahinAccess: kSecAttrAccessibleAlways)
        do {
            let sign = try security.sign(Data: rawData, PrivateKey: "PrivateKeyID")
            XCTAssertNotNil(sign)
            
            let verify = try security.verify(RawData: rawData, SignedData: sign!, PublicKey: "PublicKeyID")
            XCTAssertTrue(verify)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_6_encrypt() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        do {
            let cipher = try security.encrypt(Plain: plainText, Key: "PublicKeyID")
            
            XCTAssertNotNil(cipher)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_7_decrypt() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        do {
            let cipher = try security.encrypt(Plain: plainText, Key: "PublicKeyID")
            XCTAssertNotNil(cipher)
            
            let plain = try security.decrypt(Cipher: cipher!, Key: "PrivateKeyID")
            XCTAssertNotNil(plain)
            XCTAssertEqual(plain, plainText)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }

    func test_8_generateKeyPairWithoutSaving() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        let (pubKey, pKey) = security.generateKeyPair()
    
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }

    func test_9_calculateShareSecrets_ID() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        let _ = security.generateKeyPair(PublicKeyID: "PubKeyID1", PrivateKeyID: "PvKeyID1")
        let _ = security.generateKeyPair(PublicKeyID: "PubKeyID2", PrivateKeyID: "PvKeyID2")
        
        let sharedSecret1 = try? security.calculateSharedSecret(PrivateKey: "PvKeyID1", PublicKey: "PubKeyID2", Parameters: [:])
        let sharedSecret2 = try? security.calculateSharedSecret(PrivateKey: "PvKeyID2", PublicKey: "PubKeyID1", Parameters: [:])
        
        XCTAssertNotNil(sharedSecret1 as Any)
        XCTAssertNotNil(sharedSecret2 as Any)
        XCTAssertEqual(sharedSecret1, sharedSecret2)
        
        let wrongSharedSecret = try? security.calculateSharedSecret(PrivateKey: "PvKeyID2", PublicKey: "PublicKeyID", Parameters: [:])
        XCTAssertNotEqual(sharedSecret1, wrongSharedSecret)
    }
    
    func test_9_calculateShareSecrets_Data() {
        let security = Security(KeycahinAccess: kSecAttrAccessibleAlways)
        
        let pubKey1Data: Data = security.getKey(ID: "PubKeyID1")!
        let pubKey2Data: Data = security.getKey(ID: "PubKeyID2")!
        let pvKey1Data: Data = security.getKey(ID: "PvKeyID1")!
        let pvKey2Data: Data = security.getKey(ID: "PvKeyID2")!
        
        let sharedSecret1 = try? security.calculateSharedSecret(PrivateKey: pvKey1Data, PublicKey: pubKey2Data, Parameters: [:])
        let sharedSecret2 = try? security.calculateSharedSecret(PrivateKey: pvKey2Data, PublicKey: pubKey1Data, Parameters: [:])
        
        XCTAssertNotNil(sharedSecret1 as Any)
        XCTAssertNotNil(sharedSecret2 as Any)
        XCTAssertEqual(sharedSecret1, sharedSecret2)
        
        let pubKeyWrongData: Data = security.getKey(ID: "PublicKeyID")!
        let wrongSharedSecret = try? security.calculateSharedSecret(PrivateKey: pvKey2Data, PublicKey: pubKeyWrongData, Parameters: [:])
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
