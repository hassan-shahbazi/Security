//
//  Keychain.swift
//  Raha
//
//  Created by Hassaniiii on 1/10/1396 AP.
//  Copyright © 1396 AP Hassan Shahbazi. All rights reserved.
//

import Foundation
import Security

// Constant Identifiers
let userAccount = "AuthenticatedUser"
let accessGroup = "SecuritySerivice"


/**
 *  User defined keys for new entry
 *  Note: add new keys for new secure item and use them in load and save methods
 */

// Arguments for the keychain queries
let kSecClassValue = NSString(format: kSecClass)
let kSecAttrAccountValue = NSString(format: kSecAttrAccount)
let kSecValueDataValue = NSString(format: kSecValueData)
let kSecClassGenericPasswordValue = NSString(format: kSecClassGenericPassword)
let kSecAttrServiceValue = NSString(format: kSecAttrService)
let kSecMatchLimitValue = NSString(format: kSecMatchLimit)
let kSecReturnDataValue = NSString(format: kSecReturnData)
let kSecMatchLimitOneValue = NSString(format: kSecMatchLimitOne)

class Keychain: NSObject {

    /**
     * Exposed methods to perform save and load queries.
     */
    public class func saveKey(token: String, id: String) {
        self.save(service: id, data: token)
    }
    
    public class func loadKey(id: String) -> String? {
        return self.load(service: id)
    }
    
    /**
     * Internal methods for querying the keychain.
     */
    
    private class func save(service: String, data: String) {
        let dataFromString = data.data(using: String.Encoding.utf8, allowLossyConversion: false)!
        
        // Instantiate a new default keychain query
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue,
                                                                               service,
                                                                               userAccount,
                                                                               dataFromString],
                                                                     forKeys: [kSecClassValue,
                                                                               kSecAttrServiceValue,
                                                                               kSecAttrAccountValue,
                                                                               kSecValueDataValue])
        
        // Delete any existing items
        SecItemDelete(keychainQuery as CFDictionary)
        
        // Add the new keychain item
        SecItemAdd(keychainQuery as CFDictionary, nil)
    }
    
    private class func load(service: String) -> String? {
        // Instantiate a new default keychain query
        // Tell the query to return a result
        // Limit our results to one item
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue,
                                                                               service,
                                                                               userAccount,
                                                                               kCFBooleanTrue,
                                                                               kSecMatchLimitOneValue],
                                                                     forKeys: [kSecClassValue,
                                                                               kSecAttrServiceValue,
                                                                               kSecAttrAccountValue,
                                                                               kSecReturnDataValue,
                                                                               kSecMatchLimitValue])
        
        var dataTypeRef :AnyObject?
        
        // Search for the keychain items
        let status: OSStatus = SecItemCopyMatching(keychainQuery, &dataTypeRef)
        var contentsOfKeychain: String? = nil
        
        if status == errSecSuccess {
            if let retrievedData = dataTypeRef as? Data {
                contentsOfKeychain = String(data: retrievedData,
                                            encoding: String.Encoding(rawValue: String.Encoding.utf8.rawValue))
            }
        }
        
        return contentsOfKeychain
    }

}
