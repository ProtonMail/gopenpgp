# GopenPGP V2

GopenPGP is a high-level OpenPGP library built on top of [a fork of the golang
crypto library](https://github.com/ProtonMail/crypto).

**Table of Contents**

<!-- TOC depthFrom:2 -->

- [Download/Install](#downloadinstall)
- [Documentation](#documentation)
- [Using with Go Mobile](#using-with-go-mobile)
- [Other notes](#other-notes)
- [Full documentation](#full-documentation)
- [Examples](#examples)
    - [Set up](#set-up)
    - [Encrypt / Decrypt with password](#encrypt--decrypt-with-password)
    - [Encrypt / Decrypt with PGP keys](#encrypt--decrypt-with-pgp-keys)
    - [Generate key](#generate-key)
    - [Detached signatures for plain text messages](#detached-signatures-for-plain-text-messages)
    - [Detached signatures for binary data](#detached-signatures-for-binary-data)
    - [Cleartext signed messages](#cleartext-signed-messages)

<!-- /TOC -->

## Download/Install

This package uses [Go Modules](https://github.com/golang/go/wiki/Modules), and
thus requires Go 1.11+. If you're also using Go Modules, simply import it and
start using it (see [Set up](#set-up)). If not, run:

```bash
go get github.com/ProtonMail/gopenpgp # or git clone this repository into the following path
cd $GOPATH/src/github.com/ProtonMail/gopenpgp
GO111MODULE=on go mod vendor
```

(After that, the code will also work in Go 1.10, but you need Go 1.11 for the `go mod` command.)

## Documentation

https://godoc.org/gopkg.in/ProtonMail/gopenpgp.v2/crypto

## Using with Go Mobile

Setup Go Mobile and build/bind the source code:

Go Mobile repo: https://github.com/golang/mobile
Go Mobile wiki: https://github.com/golang/go/wiki/Mobile

1. Install Go: `brew install go`
2. Install Gomobile: `go get -u golang.org/x/mobile/cmd/gomobile`
3. Install Gobind: `go install golang.org/x/mobile/cmd/gobind`
4. Install Android SDK and NDK using Android Studio
5. Set env: `export ANDROID_HOME="/AndroidSDK"` (path to your SDK)
6. Init gomobile: `gomobile init -ndk /AndroidSDK/ndk-bundle/` (path to your NDK)
7. Copy Go module dependencies to the vendor directory: `go mod vendor`
8. Build examples:
   `gomobile build -target=android  #or ios`

   Bind examples:
   `gomobile bind -target ios -o frameworks/name.framework`
   `gomobile bind -target android`

   The bind will create framework for iOS and jar&aar files for Android (x86_64 and ARM).

## Other notes

If you wish to use build.sh, you may need to modify the paths in it.

Interfacing between Go and Swift:
https://medium.com/@matryer/tutorial-calling-go-code-from-swift-on-ios-and-vice-versa-with-gomobile-7925620c17a4.

## Examples

### Set up

```go
import "github.com/ProtonMail/gopenpgp/crypto"
```

### Encrypt / Decrypt with password

```gotemplate
import "github.com/ProtonMail/gopenpgp/v2/helper"

const password = []byte("hunter2")

// Encrypt data with password
armor, err := helper.EncryptMessageWithPassword(password, "my message")

// Decrypt data with password
message, err := helper.DecryptMessageWithPassword(password, armor)
```

To encrypt binary data or use more advanced modes:
```gotemplate
import "github.com/ProtonMail/gopenpgp/v2/constants"

const password = []byte("hunter2")

var message = crypto.NewPlainMessage(data)
// Or
message = crypto.NewPlainMessageFromString(string)

// Encrypt data with password
encrypted, err := EncryptMessageWithPassword(message, password)
// Encrypted message in encrypted.GetBinary() or encrypted.GetArmored()

// Decrypt data with password
decrypted, err := DecryptMessageWithPassword(encrypted, password)

//Original message in decrypted.GetBinary()
```

### Encrypt / Decrypt with PGP keys

```gotemplate
import "github.com/ProtonMail/gopenpgp/v2/helper"

// put keys in backtick (``) to avoid errors caused by spaces or tabs
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key

const passphrase = []byte(`the passphrase of the private key`) // Passphrase of the privKey

// encrypt message using public key
armor, err := helper.EncryptMessageArmored(pubkey, "plain text")

// decrypt armored encrypted message using the private key
decrypted, err := helper.DecryptMessageArmored(privkey, passphrase, armor)
```

With signatures:
```gotemplate
// Keys initialization as before (omitted)

// encrypt message using public key, sign with the private key
armor, err := helper.EncryptSignMessageArmored(pubkey, privkey, passphrase, "plain text")

// decrypt armored encrypted message using the private key, verify with the public key
// err != nil if verification fails
decrypted, err := helper.DecryptVerifyMessageArmored(pubkey, privkey, passphrase, armor)
```

With binary data or advanced modes:
```gotemplate
// Keys initialization as before (omitted)
var binMessage = crypto.NewPlainMessage(data)

publicKeyObj, err := crypto.NewKeyFromArmored(publicKey)
publicKeyRing, err := crypto.NewKeyFromArmored(publicKeyObj)

pgpMessage, err := publicKeyRing.Encrypt(binMessage, privateKeyRing)

// Armored message in pgpMessage.GetArmored()
// pgpMessage can be obtained from NewPGPMessageFromArmored(ciphertext)

privateKeyObj, err := crypto.NewKeyFromArmored(privateKey)
unlockedKeyObj = privateKeyObj.Unlock(passphrase)
privateKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)

message, err := privateKeyRing.Decrypt(pgpMessage, publicKeyRing, crypto.GetUnixTime())

privateKeyRing.ClearPrivateParams()

// Original data in message.GetString()
// `err` can be a SignatureVerificationError
```

### Generate key
Keys are generated with the `GenerateKey` function, that returns the armored key as a string and a potential error.
The library supports RSA with different key lengths or Curve25519 keys.

```gotemplate
const (
  name = "Max Mustermann"
  email = "max.mustermann@example.com"
  passphrase = []byte("LongSecret")
  rsaBits = 2048
)

// RSA, string
rsaKey, err := helper.GenerateKey(name, email, passphrase, "rsa", rsaBits)

// Curve25519, string
ecKey, err := helper.GenerateKey(name, email, passphrase, "x25519", 0)

// RSA, Key struct
rsaKey, err := crypto.GenerateKey(name, email, "rsa", rsaBits)

// Curve25519, Key struct
ecKey, err := crypto.GenerateKey(name, email, "x25519", 0)
```

### Detached signatures for plain text messages

To sign plain text data either an unlocked private keyring or a passphrase must be provided.
The output is an armored signature.

```gotemplate
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // Encrypted private key
const passphrase = []byte("LongSecret") // Private key passphrase 

var message = crypto.NewPlaintextMessage("Verified message")

privateKeyObj, err := crypto.NewKeyFromArmored(privkey)
unlockedKeyObj = privateKeyObj.Unlock(passphrase)
signingKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)

pgpSignature, err := signingKeyRing.SignDetached(message, trimNewlines)

// The armored signature is in pgpSignature.GetArmored()
// The signed text is in message.GetString()
```

To verify a signature either private or public keyring can be provided.

```gotemplate
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

message := crypto.NewPlaintextMessage("Verified message")
pgpSignature, err := crypto.NewPGPSignatureFromArmored(signature)

publicKeyObj, err := crypto.NewKeyFromArmored(pubkey)
signingKeyRing, err := crypto.NewKeyFromArmored(publicKeyObj)

err := signingKeyRing.VerifyDetached(message, pgpSignature, crypto.GetUnixTime())

if err == nil {
  // verification success
}
```

### Detached signatures for binary data

```gotemplate
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
const passphrase = "LongSecret"

var message = crypto.NewPlainMessage(data)

privateKeyObj, err := crypto.NewKeyFromArmored(privkey)
unlockedKeyObj = privateKeyObj.Unlock(passphrase)
signingKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)

pgpSignature, err := signingKeyRing.SignDetached(message)

// The armored signature is in pgpSignature.GetArmored()
// The signed text is in message.GetBinary()
```

To verify a signature either private or public keyring can be provided.

```gotemplate
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

message := crypto.NewPlainMessage("Verified message")
pgpSignature, err := crypto.NewPGPSignatureFromArmored(signature)

publicKeyObj, err := crypto.NewKeyFromArmored(pubkey)
signingKeyRing, err := crypto.NewKeyFromArmored(publicKeyObj)

err := signingKeyRing.VerifyDetached(message, pgpSignature, crypto.GetUnixTime())

if err == nil {
  // verification success
}
```

### Cleartext signed messages
```gotemplate
// Keys initialization as before (omitted)
armored, err := helper.SignCleartextMessageArmored(privateKey, passphrase, plaintext)
```

To verify the message it has to be provided unseparated to the library.
If verification fails an error will be returned.
```gotemplate
// Keys initialization as before (omitted)
verifiedPlainText, err := helper.VerifyCleartextMessageArmored(publicKey, armored, crypto.GetUnixTime())
```

### Encrypting and decrypting session Keys
A session key can be generated, encrypted to a Asymmetric/Symmetric key packet and obtained from it
```gotemplate
// Keys initialization as before (omitted)

sessionKey, err := crypto.GenerateSessionKey()

keyPacket, err := publicKey.EncryptSessionKey(sessionKey)
keyPacketSymm, err := crypto.EncryptSessionKeyWithPassword(sessionKey, password)
```
`KeyPacket` is a `[]byte` containing the session key encrypted with the private key or password.

```gotemplate
decodedKeyPacket, err := privateKey.DecryptSessionKey(keyPacket)
decodedSymmKeyPacket, err := crypto.DecryptSessionKeyWithPassword(keyPacketSymm, password)
```
`decodedKeyPacket` and `decodedSymmKeyPacket` are objects of type `*SymmetricKey` that can
be used to decrypt the corresponding symmetrically encrypted data packets:

```gotemplate
var message = crypto.NewPlainMessage(data)

// Encrypt data with password
dataPacket, err := sessionKey.Encrypt(message)

// Decrypt data with password
decrypted, err := sessionKey.Decrypt(password, dataPacket)

//Original message in decrypted.GetBinary()
```

Note that it is not possible to process signatures when using data packets directly.
Joining the data packet and a key packet gives us a valid PGP message:

```gotemplate
pgpSplitMessage := NewPGPSplitMessage(keyPacket, dataPacket)
pgpMessage := pgpSplitMessage.GetPGPMessage()

// And vice-versa
newPGPSplitMessage, err := pgpMessage.SeparateKeyAndData()
// Key Packet is in newPGPSplitMessage.GetKeyPacket()
// Data Packet is in newPGPSplitMessage.GetDataPacket()
```