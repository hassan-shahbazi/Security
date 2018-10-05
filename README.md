# Security
![Build_Status](https://travis-ci.org/Hassaniiii/Security.svg?branch=master)
![cocoapods compatible](https://img.shields.io/badge/Cocoapods-compatible-4BC51D.svg?style=flat)
![Licence](https://img.shields.io/github/license/Hassaniiii/Security.svg)

**SecurityWrapper** is a simple security framework letting you to use security functions with a few lines of code. It supports both Symmetric and Asymmetric algorithms, Signing and Verifying and key agreement using Diffie-Hellman algorithm.

## Requirements

- Xcode 10
    
    Since **CommonCrypto** library has been available for Swift projects since xcode10, you'll need to checkout [**xcode9**](https://github.com/Hassaniiii/Security/tree/xcode9) branch if you want to use SecurityWrapper with earlier versions of xcode.

- Swift 4.0+

## Installation
`SecurityWrapper` is accessible on the `cocoapods`. Edit your project's `Podfile` and add following line to it:

`pod 'SecurityWrapper'`

## Usage
It consists of 3 main sections. Asymmetric, Symmetric, and Hashing. To find more examples and usages you can take a look at
 [AsymmetricTests](https://github.com/Hassaniiii/Security/blob/master/SecurityWrapperTests/SecurityWrapperTests.swift), [SymmetricTests](https://github.com/Hassaniiii/Security/blob/master/SecurityWrapperTests/SymmetricTests.swift) and [HashingTests](https://github.com/Hassaniiii/Security/blob/master/SecurityWrapperTests/HashingTests.swift).

## Symmetric

### Encrypt - Decrypt
```swift
let security = Symmetric()
let key = security.generateSymmetricKey(id: "AESKeyID")

let cipher = security.encrypt(plain: plain, key: key!, iv: iv!)
let plain = security.decrypt(cipher: cipher!, key: key!, iv: iv!)
```

## Asymmetric

### Encrypt - Decrypt
```swift
let security = Asymmetric()
let (pubKey, pKey) = security.generateKeyPair(publicKeyID: "PublicKeyID", privateKeyID: "PrivateKeyID")

let cipher = try? security.encrypt(text: plainText, keyID: "PublicKeyID")
let plain = try? security.decrypt(cipher: cipher!, keyID: "PrivateKeyID")
```

### Signing - Verifying
```swift
let security = Asymmetric(signAlgo: .ecdsaSignatureDigestX962SHA512)

let sign = try? security.sign(data: rawData, privateKeyID: "PrivateKeyID")
let verify = try? security.verify(rawData: rawData, signedData: sign!, publicKeyID: "PublicKeyID")
```

### Key agreement (Diffie Hellman)
```swift
let security = Asymmetric()
let yourPrivateKey: Data = security.getKey(id: "PvKeyID1")!
let peerPublicKey: Data = *Peer Public Key*

let sharedSecret = try? security.computeSharedSecret(privateKey: yourPrivateKey, publicKey: peerPublicKey)
```

## Hash
```swift
var hash = Hash(.MD5)
let MD5 = hash.hash(plainData)

hash = Hash(.SHA256)
let SHA256 = hash.hash(plainData)

hash = Hash(.SHA512)
let SHA512 = hash.hash(plainData)
```

## HMAC
```swift
var hash = Hash(.SHA1)
let HMAC1 = hash.hmac(message: plainData, key: plainKey)

hash = Hash(.SHA256)
let HMAC256 = hash.hmac(message: plainData, key: plainKey)

hash = Hash(.SHA512)
let HMAC512 = hash.hmac(message: plainData, key: plainKey)
```

## Contribution
Please ensure your pull request adheres to the following guidelines:

* Alphabetize your entry.
* Search previous suggestions before making a new one, as yours may be a duplicate.
* Suggested READMEs should be beautiful or stand out in some way.
* Make an individual pull request for each suggestion.
* New categories, or improvements to the existing categorization are welcome.
* Keep descriptions short and simple, but descriptive.
* Start the description with a capital and end with a full stop/period.
* Check your spelling and grammar.
* Make sure your text editor is set to remove trailing whitespace.

Thank you for your suggestions!

## Authors
* **Hassan Shahbazi** - [Hassaniiii](https://github.com/Hassaniiii)

## License
This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/Hassaniiii/Security/blob/master/LICENSE.md) file for details
