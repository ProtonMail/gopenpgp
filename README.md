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

1. Run `go get -u github.com/ProtonMail/gopenpgp`, or manually `git clone` this
   repository into `$GOPATH/src/github.com/ProtonMail/gopenpgp`.

2. [Install Glide](https://github.com/Masterminds/glide#install):

   ```bash
   curl https://glide.sh/get | sh
   ```

3. Install dependencies using glide:

   ```bash
   cd $GOPATH/src/github.com/ProtonMail/gopenpgp
   glide install
   ```

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

7. Build examples:
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

privateKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(privkey))
publicKeyRing, err := crypto.ReadArmoredKeyRing(strings.NewReader(pubkey))

// encrypt message using public key and can be optionally signed using private key and passphrase
armor, err := pgp.EncryptMessage("plain text", publicKeyRing, privateKeyRing, passphrase, false)
// OR
privateKeyRing.Unlock([]byte(passphrase)) // if private key is locked with passphrase
armor, err := publicKeyRing.EncryptString("plain text", privateKeyRing)

// decrypt armored encrypted message using the private key and the passphrase of the private key
plainText, err := pgp.DecryptMessage(armor, privateKeyRing, passphrase)
// OR
signedText, err := privateKeyRing.DecryptString(armor)
plainText = signedText.String

```

### Generate key

Keys are generated with the `GenerateKey` function, that returns the armored key as a string and a potential error.
The library supports RSA with different key lengths or Curve25519 keys.

```go
var pgp = crypto.GopenPGP{}

var (
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

signingKeyRing, err := ReadArmoredKeyRing(strings.NewReader(privkey))

signature, err := pgp.SignTextDetached(plaintext, signingKeyRing, passphrase, trimNewlines)
// or
signingKeyRing.Unlock([]byte(passphrase))
signature, err := pgp.SignTextDetached(plaintext, signingKeyRing, "", trimNewlines)
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

signingKeyRing, err := ReadArmoredKeyRing(strings.NewReader(pubkey))

verified, err := pgp.VerifyTextDetachedSig(signature, signedPlainText, signingKeyRing, verifyTime)
```

### Detached signatures for binary data

To sign binary data either an unlocked private keyring or a passphrase must be provided.
The output is an armored signature.

```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
passphrase = "LongSecret"
const trimNewlines = false

signingKeyRing, err := ReadArmoredKeyRing(strings.NewReader(privkey))

signature, err := pgp.SignBinDetached(data, signingKeyRing, passphrase, trimNewlines)
// or
signingKeyRing.Unlock([]byte(passphrase))
signature, err := pgp.SignBinDetached(data, signingKeyRing, "", trimNewlines)
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

signingKeyRing, err := ReadArmoredKeyRing(strings.NewReader(pubkey))

verified, err := pgp.VerifyBinDetachedSig(signature, data, signingKeyRing, verifyTime)
```
