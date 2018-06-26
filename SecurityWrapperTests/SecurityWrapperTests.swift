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
    
    func test_A_keyGeneration() {
        let security = Asymmetric()
        let (pubKey, pKey) = security.generateKeyPair(publicKeyID: "PublicKeyID", privateKeyID: "PrivateKeyID")
        
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }
    
    func test_B_keyData() {
        let security = Asymmetric()
        let pubkey: Data? = security.getKey(id: "PublicKeyID")
        let pkey: Data? = security.getKey(id: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_C_keyRef() {
        let security = Asymmetric()
        let pubkey: SecKey? = security.getKey(id: "PublicKeyID")
        let pkey: SecKey? = security.getKey(id: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_D_signData() {
        let security = Asymmetric(signAlgo: .ecdsaSignatureDigestX962SHA512)
        do {
            let sign = try security.sign(data: rawData, privateKeyID: "PrivateKeyID")
            XCTAssertNotNil(sign)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_E_verifySign() {
        let security = Asymmetric(signAlgo: .ecdsaSignatureDigestX962SHA512)
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
    
    func test_F_encrypt() {
        let security = Asymmetric()
        do {
            let cipher = try security.encrypt(text: plainText, keyID: "PublicKeyID")
            
            XCTAssertNotNil(cipher)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }
    
    func test_G_decrypt() {
        let security = Asymmetric()
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

    func test_H_generateKeyPairWithoutSaving() {
        let security = Asymmetric()
        let (pubKey, pKey) = security.generateKeyPair()
    
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }

    func test_I_calculateSharedSecrets_ID() {
        let security = Asymmetric()
        let _ = security.generateKeyPair(publicKeyID: "PubKeyID1", privateKeyID: "PvKeyID1")
        let _ = security.generateKeyPair(publicKeyID: "PubKeyID2", privateKeyID: "PvKeyID2")
        
        let sharedSecret1 = try? security.computeSharedSecret(privateKey: "PvKeyID1", publicKey: "PubKeyID2")
        let sharedSecret2 = try? security.computeSharedSecret(privateKey: "PvKeyID2", publicKey: "PubKeyID1")
        
        XCTAssertNotNil(sharedSecret1 as Any)
        XCTAssertNotNil(sharedSecret2 as Any)
        XCTAssertEqual(sharedSecret1!, sharedSecret2!)
        
        let wrongSharedSecret = try? security.computeSharedSecret(privateKey: "PvKeyID2", publicKey: "PublicKeyID")
        XCTAssertNotEqual(sharedSecret1!, wrongSharedSecret!)
    }
    
    func test_J_calculateSharedSecrets_Data() {
        let security = Asymmetric()
        
        let pubKey1Data: Data = security.getKey(id: "PubKeyID1")!
        let pubKey2Data: Data = security.getKey(id: "PubKeyID2")!
        let pvKey1Data: Data = security.getKey(id: "PvKeyID1")!
        let pvKey2Data: Data = security.getKey(id: "PvKeyID2")!
        
        let sharedSecret1 = try? security.computeSharedSecret(privateKey: pvKey1Data, publicKey: pubKey2Data)
        let sharedSecret2 = try? security.computeSharedSecret(privateKey: pvKey2Data, publicKey: pubKey1Data)
        
        XCTAssertNotNil(sharedSecret1 as Any)
        XCTAssertNotNil(sharedSecret2 as Any)
        XCTAssertEqual(sharedSecret1!, sharedSecret2!)
        
        let pubKeyWrongData: Data = security.getKey(id: "PublicKeyID")!
        let wrongSharedSecret = try? security.computeSharedSecret(privateKey: pvKey2Data, publicKey: pubKeyWrongData)
        XCTAssertNotEqual(sharedSecret1!, wrongSharedSecret!)
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
