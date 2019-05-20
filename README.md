# GopenPGP

GopenPGP is a high-level OpenPGP library built on top of [a fork of the golang
crypto library](https://github.com/ProtonMail/crypto).

**Table of Contents**

<!-- TOC depthFrom:2 -->

- [Download/Install](#downloadinstall)
- [Documentation](#documentation)
- [Using with Go Mobile](#using-with-go-mobile)
- [Other notes](#other-notes)
- [Examples](#examples)
    - [Set up](#set-up)
    - [Encrypt and decrypt](#encrypt-and-decrypt)
        - [Encrypt / Decrypt with password](#encrypt--decrypt-with-password)
        - [Encrypt / Decrypt with PGP keys](#encrypt--decrypt-with-pgp-keys)
    - [Generate key](#generate-key)
    - [Sign plain text messages](#sign-plain-text-messages)
    - [Detached signatures for binary data](#detached-signatures-for-binary-data)

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

https://godoc.org/github.com/ProtonMail/gopenpgp/crypto

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

## Full documentation
The full documentation for this API is available here: https://godoc.org/gopkg.in/ProtonMail/gopenpgp.v0/crypto

## Examples

### Set up

```go
import "github.com/ProtonMail/gopenpgp/crypto"
```

### Encrypt / Decrypt with password

```go
var pgp = crypto.GopenPGP{}

const password = "my secret password"

// Encrypt data with password
armor, err := pgp.EncryptMessageAES256Helper(password, "my message")

// Decrypt data with password
message, err := pgp.DecryptMessageSymmetricHelper(password, armor)
```

To use more encryption algorithms:
```go
import "github.com/ProtonMail/gopenpgp/constants"
var pgp = crypto.GopenPGP{}

// Encrypt data with password
armor, err := pgp.EncryptMessageSymmetricHelper(password, "my message", constants.ThreeDES)

// Decrypt data with password
message, err := pgp.DecryptMessageSymmetricHelper(password, armor)
```

To encrypt binary data, reuse the key multiple times, or use more advanced modes:
```go
import "github.com/ProtonMail/gopenpgp/constants"
var pgp = crypto.GopenPGP{}

var key = crypto.NewSymmetricKey("my secret password", constants.AES256)
var message = crypto.BinaryMessage(data)

// Encrypt data with password
encrypted, err := key.Encrypt(message)

// Decrypt data with password
decrypted, err := key.Decrypt(password, encrypted)

//Original message in decrypted.GetBinary()
```

### Encrypt / Decrypt with PGP keys

```go
var pgp = crypto.GopenPGP{}

// put keys in backtick (``) to avoid errors caused by spaces or tabs
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key

const passphrase = `the passphrase of the private key` // what the privKey is encrypted with

// encrypt message using public key
armor, err := pgp.EncryptMessageArmoredHelper(pubkey, "plain text")

// decrypt armored encrypted message using the private key
decrypted, err := pgp.DecryptMessage(privkey, passphrase, armor)
```

With signatures:
```go
// Keys initialization as before (omitted)

// encrypt message using public key, sign with the private key
armor, err := pgp.EncryptSignMessageArmoredHelper(pubkey, privkey, passphrase, "plain text")

// decrypt armored encrypted message using the private key, verify with the public key
// err != nil if verification fails
decrypted, err := pgp.DecryptVerifyMessageArmoredHelper(pubkey, privkey, passphrase, armor)
```

With binary data or advanced modes:
```go

var binMessage = NewBinaryMessage(data)

publicKeyRing, err := pgp.BuildKeyRingArmored(publicKey)
privateKeyRing, err := pgp.BuildKeyRingArmored(privateKey)
err = privateKeyRing.UnlockWithPassphrase(passphrase)
pgpMessage, err := publicKeyRing.Encrypt(binMessage, privateKeyRing)

// Armored message in pgpMessage.GetArmored()
// pgpMessage obtained from NewPGPMessageFromArmored(ciphertext)

cleartextMessage, err := privateKeyRing.Decrypt(pgpMessage, publicKeyRing, pgp.GetUnixTime())

// Original data in cleartextMessage.GetString()
if cleartextMessage.IsVerified() {
  // verification success
}
```
### Generate key

Keys are generated with the `GenerateKey` function, that returns the armored key as a string and a potential error.
The library supports RSA with different key lengths or Curve25519 keys.

```go
var pgp = crypto.GopenPGP{}

const (
  localPart = "name.surname"
  domain = "example.com"
  passphrase = "LongSecret"
  rsaBits = 2048
  ecBits = 256
)

// RSA
rsaKey, err := pgp.GenerateKey(localPart, domain, passphrase, "rsa", rsaBits)

// Curve25519
ecKey, err := pgp.GenerateKey(localPart, domain, passphrase, "x25519", ecBits)
```

### Detached signatures for plain text messages

To sign plain text data either an unlocked private keyring or a passphrase must be provided.
The output is an armored signature.

```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
const passphrase = "LongSecret"
const trimNewlines = false

var message = NewPlaintextMessage("Verified message")

signingKeyRing, err := pgp.BuildKeyRingArmored(privkey)
signingKeyRing.UnlockWithPassphrase(passphrase) // if private key is locked with passphrase

message, pgpSignature, err := signingKeyRing.SignMessage(message, trimNewlines)

// The armored signature is in pgpSignature.GetArmored()
// The signed text is in message.GetString()
```

To verify a signature either private or public keyring can be provided.

```go
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

message := NewPlaintextMessage("Verified message")
pgpSignature, err := NewPGPSignatureFromArmored(signature)
signingKeyRing, err := pgp.BuildKeyRingArmored(pubkey)

message, err := signingKeyRing.VerifyMessage(message, pgpSignature, pgp.GetUnixTime())

if message.IsVerified() {
  // verification success
}
```

### Detached signatures for binary data

```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
const passphrase = "LongSecret"

var message = NewBinaryMessage(data)

signingKeyRing, err := pgp.BuildKeyRingArmored(privkey)
signingKeyRing.UnlockWithPassphrase(passphrase) // if private key is locked with passphrase

message, pgpSignature, err := signingKeyRing.Sign(message)

// The armored signature is in pgpSignature.GetArmored()
// The signed text is in message.GetBinary()
```

To verify a signature either private or public keyring can be provided.

```go
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

message := NewBinaryMessage("Verified message")
pgpSignature, err := NewPGPSignatureFromArmored(signature)
signingKeyRing, err := pgp.BuildKeyRingArmored(pubkey)

message, err := signingKeyRing.Verify(message, pgpSignature, pgp.GetUnixTime())

if message.IsVerified() {
  // verification success
}
```
