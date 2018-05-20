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
    
    func test_8_hash() {
        var hash = Hash(.MD5)
        let plainData = "Hassan Shahbazi".data(using: .utf8)!
        
        let MD5 = hash.hash(Message: plainData)
        XCTAssertNotNil(MD5)
        XCTAssertEqual("A90FFF72E4FFDD1520AAF36852B9A5AF".lowercased(), MD5?.hex)
        
        hash = Hash(.SHA1)
        let SHA1 = hash.hash(Message: plainData)
        XCTAssertNotNil(SHA1)
        XCTAssertEqual("E2DCD09FB85B41EAA2283B9DD0DC1CD251CB5340".lowercased(), SHA1?.hex)
        
        hash = Hash(.SHA256)
        let SHA256 = hash.hash(Message: plainData)
        XCTAssertNotNil(SHA256)
        XCTAssertEqual("CF7735B36C1E46FDC0F9C5019C77BB14D9B3B4B7C07D56905153D116C8A268BF".lowercased(), SHA256?.hex)
        
        hash = Hash(.SHA512)
        let SHA512 = hash.hash(Message: plainData)
        XCTAssertNotNil(SHA512)
        XCTAssertEqual("F3A5378AA5B123B5C28BD772CB8CF5C7C6A4BB09CA6E1A13E467011D752EE2822E8D6F010F217C59D3783713AB0510740129EA14BC300357EAFA97EC64BD9619".lowercased(), SHA512?.hex)
    }
    
    func test_9_hmac() {
        var hash = Hash(.SHA1)
        let plainData = "Hassan Shahbazi".data(using: .utf8)!
        let plainKey = "Key".data(using: .utf8)!
        
        let HMAC1 = hash.hmac(Message: plainData, Key: plainKey)
        XCTAssertNotNil(HMAC1)
        XCTAssertEqual("65691086e6815f3f677761102dedba694fcd940d", HMAC1!.hex)
        
        hash = Hash(.SHA256)
        let HMAC256 = hash.hmac(Message: plainData, Key: plainKey)
        XCTAssertNotNil(HMAC256)
        XCTAssertEqual("3c1077f559cc469db0ef6ecc508cf83e7bebf59c5ff7ea0279b6f74c34f7529c", HMAC256!.hex)
        
        hash = Hash(.SHA512)
        let HMAC512 = hash.hmac(Message: plainData, Key: plainKey)
        XCTAssertNotNil(HMAC512)
        XCTAssertEqual("82f5f1f1e0ed2bc6386e1c786787c682dc892714ce142449a62eff1c41154857ce16efa3046a921c9ee0ac74d8e2151ceeecfa56b11d6fa88d1acf9fe4dcc1c7", HMAC512!.hex)
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
