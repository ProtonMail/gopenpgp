# GopenPGP V2
[![Build Status](https://travis-ci.org/ProtonMail/gopenpgp.svg?branch=master)](https://travis-ci.org/ProtonMail/gopenpgp)

GopenPGP is a high-level OpenPGP library built on top of [a fork of the golang
crypto library](https://github.com/ProtonMail/crypto).

**Table of Contents**

<!-- TOC depthFrom:2 -->

- [Download/Install](#downloadinstall)
- [Documentation](#documentation)
- [Using with Go Mobile](#using-with-go-mobile)
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
### Vendored install
To use this library using [Go Modules](https://github.com/golang/go/wiki/Modules) just edit your
`go.mod` configuration to contain:
```gomod
require (
    ...
    github.com/ProtonMail/gopenpgp/v2 v2.0.1
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200416114516-1fa7f403fb9c
```

It can then be installed by running:
```sh
go mod vendor
```
Finally your software can include it in your software as follows:
```go
package main

import (
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func main() {
	fmt.Println(crypto.GetUnixTime())
}
```

### Git-Clone install
To install for development mode, cloning the repository, it can be done in the following way:
```bash
cd $GOPATH
mkdir -p src/github.com/ProtonMail/
cd $GOPATH/src/github.com/ProtonMail/
git clone git@github.com:ProtonMail/gopenpgp.git
cd gopenpgp
ln -s . v2
go mod
```

## Documentation
A full overview of the API can be found here:
https://godoc.org/gopkg.in/ProtonMail/gopenpgp.v2/crypto

In this document examples are provided and the proper use of (almost) all functions is tested.

## Using with Go Mobile
This library can be compiled with [Gomobile](https://github.com/golang/go/wiki/Mobile) too.
First ensure you have a working installation of gomobile:
```bash
gomobile version
```
In case this fails, install it with:
```bash
go get -u golang.org/x/mobile/cmd/gomobile
```
Then ensure your path env var has gomobile's binary, and it is properly init-ed:
```bash
export PATH="$PATH:$GOPATH/bin"
gomobile init
```
Then you must ensure that the Android or iOS frameworks are installed and the respective env vars set.

Finally, build the application
```bash
sh build.sh
```
This script will build for both android and iOS at the same time,
to filter one out you can comment out the line in the corresponding section.

## Examples

### Encrypt / Decrypt with password

```go
import "github.com/ProtonMail/gopenpgp/v2/helper"

const password = []byte("hunter2")

// Encrypt data with password
armor, err := helper.EncryptMessageWithPassword(password, "my message")

// Decrypt data with password
message, err := helper.DecryptMessageWithPassword(password, armor)
```

To encrypt binary data or use more advanced modes:
```go
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

```go
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
```go
// Keys initialization as before (omitted)

// encrypt message using public key, sign with the private key
armor, err := helper.EncryptSignMessageArmored(pubkey, privkey, passphrase, "plain text")

// decrypt armored encrypted message using the private key, verify with the public key
// err != nil if verification fails
decrypted, err := helper.DecryptVerifyMessageArmored(pubkey, privkey, passphrase, armor)
```

With binary data or advanced modes:
```go
// Keys initialization as before (omitted)
var binMessage = crypto.NewPlainMessage(data)

publicKeyObj, err := crypto.NewKeyFromArmored(publicKey)
publicKeyRing, err := crypto.NewKeyRing(publicKeyObj)

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

```go
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

```go
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

```go
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const signature = `-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`

message := crypto.NewPlaintextMessage("Verified message")
pgpSignature, err := crypto.NewPGPSignatureFromArmored(signature)

publicKeyObj, err := crypto.NewKeyFromArmored(pubkey)
signingKeyRing, err := crypto.NewKeyRing(publicKeyObj)

err := signingKeyRing.VerifyDetached(message, pgpSignature, crypto.GetUnixTime())

if err == nil {
  // verification success
}
```

### Detached signatures for binary data

```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // encrypted private key
const passphrase = "LongSecret"

var message = crypto.NewPlainMessage(data)

privateKeyObj, err := crypto.NewKeyFromArmored(privkey)
unlockedKeyObj := privateKeyObj.Unlock(passphrase)
signingKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)

pgpSignature, err := signingKeyRing.SignDetached(message)

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

message := crypto.NewPlainMessage("Verified message")
pgpSignature, err := crypto.NewPGPSignatureFromArmored(signature)

publicKeyObj, err := crypto.NewKeyFromArmored(pubkey)
signingKeyRing, err := crypto.NewKeyRing(publicKeyObj)

err := signingKeyRing.VerifyDetached(message, pgpSignature, crypto.GetUnixTime())

if err == nil {
  // verification success
}
```

### Cleartext signed messages
```go
// Keys initialization as before (omitted)
armored, err := helper.SignCleartextMessageArmored(privateKey, passphrase, plaintext)
```

To verify the message it has to be provided unseparated to the library.
If verification fails an error will be returned.
```go
// Keys initialization as before (omitted)
verifiedPlainText, err := helper.VerifyCleartextMessageArmored(publicKey, armored, crypto.GetUnixTime())
```

### Encrypting and decrypting session Keys
A session key can be generated, encrypted to a Asymmetric/Symmetric key packet and obtained from it
```go
// Keys initialization as before (omitted)

sessionKey, err := crypto.GenerateSessionKey()

keyPacket, err := publicKeyRing.EncryptSessionKey(sessionKey)
keyPacketSymm, err := crypto.EncryptSessionKeyWithPassword(sessionKey, password)
```
`KeyPacket` is a `[]byte` containing the session key encrypted with the private key or password.

```go
decodedKeyPacket, err := privateKeyRing.DecryptSessionKey(keyPacket)
decodedSymmKeyPacket, err := crypto.DecryptSessionKeyWithPassword(keyPacketSymm, password)
```
`decodedKeyPacket` and `decodedSymmKeyPacket` are objects of type `*SymmetricKey` that can
be used to decrypt the corresponding symmetrically encrypted data packets:

```go
var message = crypto.NewPlainMessage(data)

// Encrypt data with session key
dataPacket, err := sessionKey.Encrypt(message)

// Decrypt data with session key
decrypted, err := sessionKey.Decrypt(password, dataPacket)

//Original message in decrypted.GetBinary()
```

Note that it is not possible to process signatures when using data packets directly.
Joining the data packet and a key packet gives us a valid PGP message:

```go
pgpSplitMessage := NewPGPSplitMessage(keyPacket, dataPacket)
pgpMessage := pgpSplitMessage.GetPGPMessage()

// And vice-versa
newPGPSplitMessage, err := pgpMessage.SeparateKeyAndData()
// Key Packet is in newPGPSplitMessage.GetBinaryKeyPacket()
// Data Packet is in newPGPSplitMessage.GetBinaryDataPacket()
```

### Checking keys
In order to check that the primary key is valid the `Key#Check` function can be used.
This operation is as of 2.0.0 fairly expensive, as it requires a signature operation.
It will be improved in the future versions, and possibly expanded to the subkeys, that are
for now assumed to be correct thanks to the binding signature.
```go
const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // Encrypted private key
const passphrase = []byte("LongSecret") // Private key passphrase

privateKeyObj, err := crypto.NewKeyFromArmored(privkey)
unlockedKeyObj = privateKeyObj.Unlock(passphrase)

isVerified, _ := unlockedKeyObj.Check();
if !isVerified {
    // Handle broken keys
}
```
This function runs on unlocked private keys, and it will return an error if called with public keys
or locked keys.
