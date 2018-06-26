//
//  SymmetricTests.swift
//  SecurityWrapperTests
//
//  Created by Hassan Shahbazi on 2018-06-18.
//  Copyright © 2018 Hassan Shahbazi. All rights reserved.
//

import XCTest
import Security
@testable import SecurityWrapper

class SymmetricTests: XCTestCase {
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test_A_generateSymmetricKey() {
        let security = Symmetric()
        let key = security.generateSymmetricKey(id: "AESKeyID")
        XCTAssertNotNil(key)
    }
    
    func test_B_keyData() {
        let security = Symmetric()
        let AESKey = security.getKey(id: "AESKeyID")
        XCTAssertNotNil(AESKey)
    }
    
    func test_C_encrypt() {
        let security = Symmetric()
        
        let plain = "Hassan Shahbazi".data(using: .utf8)!
        let key = security.getKey(id: "AESKeyID")
        let iv = "0".data(using: .utf8)
        
        let cipher = security.encrypt(plain: plain, key: key!, iv: iv!)
        let decrypted = security.decrypt(cipher: cipher!, key: key!, iv: iv!)
        
        XCTAssertEqual(decrypted, plain)
    }
}
