# Security
![cocoapods compatible](https://img.shields.io/badge/Cocoapods-compatible-4BC51D.svg?style=flat)
![Licence](https://img.shields.io/github/license/Hassaniiii/Security.svg)

A very simple wrapper for common security implementations in iOS - Sign, Verify, Encrypt, Decrypt


## Installation
`SecurityWrapper` is compatible with `cocoapods`. Just add the following line to your `Podfile`:

`pod 'SecurityWrapper'`

## Usage
To learn how it work you can take a look at [SecurityWrapperTests.swift](https://github.com/Hassaniiii/Security/blob/master/SecurityWrapperTests/SecurityWrapperTests.swift) class. **Please note that the tests doesn't run on simulator since they need device's keychain.** You have to add a sample target to the project if you want to run the tests.  

### Key generation
```swift
let security = Security()
let (pubKey, pKey) = security.generateKeyPair(PublicKeyID: "PublicKeyID", PrivateKeyID: "PrivateKeyID")
```

### Encryption

```swift
let security = Security()
do {
    let cipher = try security.encrypt(Plain: plainText, Key: "PublicKeyID")
} catch let error {
     print(error)
}
```

### Decryption
```swift
let security = Security()
do {
    let plain = try security.decrypt(Cipher: cipher!, Key: "PrivateKeyID")
} catch let error {
     print(error)
}
```

### Key derivation
*As a `Data` instance*
```swift
let security = Security()
let pubkey: Data? = security.getKey(ID: "PublicKeyID")
let pkey: Data? = security.getKey(ID: "PrivateKeyID")
```

*As a `SecKey` instance*
```swift
let security = Security()
let pubkey: SecKey? = security.getKey(ID: "PublicKeyID")
let pkey: SecKey? = security.getKey(ID: "PrivateKeyID")
```

### Signature generation
```swift
let security = Security()
do {
    let sign = try security.sign(Data: rawData, PrivateKey: "PrivateKeyID")
} catch let error {
     print(error)
}
```

### Verify a signature
```swift
let security = Security()
do {
    let verify = try security.verify(RawData: rawData, SignedData: sign!, PublicKey: "PublicKeyID")
} catch let error {
     print(error)
}
```

### Hash
```swift
var hash = Hash(.MD5)
let MD5 = hash.hash(Message: plainData)

hash = Hash(.SHA256)
let SHA256 = hash.hash(Message: plainData)

hash = Hash(.SHA512)
let SHA512 = hash.hash(Message: plainData)
```

### HMAC
```swift
var hash = Hash(.SHA1)
let HMAC1 = hash.hmac(Message: plainData, Key: plainKey)

hash = Hash(.SHA256)
let HMAC256 = hash.hmac(Message: plainData, Key: plainKey)

hash = Hash(.SHA512)
let HMAC512 = hash.hmac(Message: plainData, Key: plainKey)
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
