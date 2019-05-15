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

## Examples

### Set up

```go
import "github.com/ProtonMail/gopenpgp/crypto"
```

### Encrypt and decrypt

Encryption and decryption will use the AES256 algorithm by default.

#### Encrypt / Decrypt with password

```go
import "github.com/ProtonMail/gopenpgp/constants"

var pgp = crypto.GopenPGP{}

const password = "my secret password"

// Encrypt data with password
armor, err := pgp.EncryptMessageWithPassword("my message", password)

// Decrypt data with password
message, err := pgp.DecryptMessageWithPassword(armor, password)
```

#### Encrypt / Decrypt with PGP keys

```go
// put keys in backtick (``) to avoid errors caused by spaces or tabs
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key

const passphrase = `the passphrase of the private key` // what the privKey is encrypted with

publicKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(pubkey))

privateKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(privkey))
privateKeyRing.UnlockWithPassphrase(passphrase) // if private key is locked with passphrase

// encrypt message using public key, can be optionally signed using private key
armor, err := publicKeyRing.EncryptMessage("plain text", privateKeyRing)

verifyTime := pgp.GetTimeUnix()
verifyKeyRing := publicKeyRing
// decrypt armored encrypted message using the private key
// optional signature verification is done through publicKeyRing and verifyTime
signedText, verified, err := privateKeyRing.DecryptMessage(armor, verifyKeyRing, verifyTime)
plainText = signedText.String

if signed == constants.SIGNATURE_OK {
  // Signature verified!
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

### Sign plain text messages

To sign plain text data either an unlocked private keyring or a passphrase must be provided.
The output is an armored signature.

```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
passphrase = "LongSecret"
const trimNewlines = false

signingKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(privkey))
signingKeyRing.UnlockWithPassphrase(passphrase) // if private key is locked with passphrase

signature, err := signingKeyRing.SignTextDetached(plaintext, trimNewlines)
// passphrase is optional if the key is already unlocked
```

To verify a signature either private or public keyring can be provided.
The newlines in the text are never trimmed in the verification process.
The function outputs a bool, if the verification fails `verified` will be false, and the error will be not `nil`.

```go
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

const verifyTime = 0
const trimNewlines = false

signingKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(pubkey))

verified, err := signingKeyRing.VerifyTextDetachedSig(signature, signedPlainText, verifyTime, trimNewlines)
```

### Detached signatures for binary data

To sign binary data either an unlocked private keyring or a passphrase must be provided.
The output is an armored signature.

```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
passphrase = "LongSecret"

signingKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(privkey))
signingKeyRing.UnlockWithPassphrase(passphrase) // if private key is locked with passphrase

signature, err := signingKeyRing.SignBinDetached(data)
```

To verify a signature either private or public keyring can be provided.
The newlines in the text are never trimmed in the verification process.
The function outputs a bool, if the verification fails `verified` will be false, and the error will be not `nil`.

```go
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

const verifyTime = 0

signingKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(pubkey))

verified, err := signingKeyRing.VerifyBinDetachedSig(signature, data, verifyTime)
```
