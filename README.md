# Security
A very simple wrapper for common security implementations in iOS - Sign, Verify, Encrypt, Decrypt


## Installation
To install and use this wrapper you have 2 options:


### Manual
Clone or download the project, then copy `Security.swift` class to your project directory

### Cocoapods
Also, you can install it using cocoapods. Just add the following line to your `Podfile`:

`pod 'SecurityWrapper', :git => "https://github.com/Hassaniiii/Security.git"`

## Usage
To learn how it work you can take a look at `SignVerifyTests.swift` class. Feel free to run tests and make sure that all things are working fine.

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
