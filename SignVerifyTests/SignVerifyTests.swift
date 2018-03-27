//
//  SignVerifyTests.swift
//  SignVerifyTests
//
//  Created by Hassan Shahbazi on 2018-03-27.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import XCTest
import Security
@testable import SignVerify

class SignVerifyTests: XCTestCase {
    
    let rawData = "t5$A1ZIPdPbyi*)n-9vDJKPfoYW%Ld35VIJ8QBgn$rCUtiRhlqWdx2Pe^O-qL%R&".data(using: .utf8)!
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test_1_keyGeneration() {
        let security = Security()
        let (pubKey, pKey) = security.generateKeyPair(PublicKeyID: "PublicKeyID", PrivateKeyID: "PrivateKeyID")
        
        XCTAssertNotNil(pubKey)
        XCTAssertNotNil(pKey)
    }
    
    func test_2_keyData() {
        let security = Security()
        let pubkey: Data? = security.getKey(ID: "PublicKeyID")
        let pkey: Data? = security.getKey(ID: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_3_keyRef() {
        let security = Security()
        let pubkey: SecKey? = security.getKey(ID: "PublicKeyID")
        let pkey: SecKey? = security.getKey(ID: "PrivateKeyID")
        
        XCTAssertNotNil(pubkey)
        XCTAssertNotNil(pkey)
    }
    
    func test_4_signSupport() {
        let security = Security(SignAlgorithm: .ecdsaSignatureDigestX962SHA256)
        XCTAssertTrue(security.checkSignVerifySupport(Key: "PrivateKeyID"))
        
        let security2 = Security(SignAlgorithm: .ecdhKeyExchangeCofactorX963SHA1)
        XCTAssertFalse(security2.checkSignVerifySupport(Key: "PrivateKeyID"))
        
        let security3 = Security(SignAlgorithm: .ecdsaSignatureDigestX962SHA1)
        XCTAssertTrue(security3.checkSignVerifySupport(Key: "PrivateKeyID"))
    }
    
    func test_5_signData() {
        let security = Security(SignAlgorithm: .ecdsaSignatureDigestX962SHA512)
        do {
            let sign = try security.sign(Data: rawData, PrivateKey: "PrivateKeyID")
            XCTAssertNotNil(sign)
        }
        catch let error {
            print(error)
            XCTAssertFalse(true)
        }
    }

    func test_6_verifySign() {
        let security = Security(SignAlgorithm: .ecdsaSignatureDigestX962SHA512)
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
}
