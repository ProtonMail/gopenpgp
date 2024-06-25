# GopenPGP V3

[![Go Report Card](https://goreportcard.com/badge/github.com/ProtonMail/gopenpgp/v3)](https://goreportcard.com/report/github.com/ProtonMail/gopenpgp/v3)
[![GoDoc](https://godoc.org/github.com/ProtonMail/gopenpgp/v3?status.svg)](https://godoc.org/github.com/ProtonMail/gopenpgp/v3)

GopenPGP V3 is a high-level OpenPGP library built on top of [a fork of the golang
crypto library](https://github.com/ProtonMail/go-crypto).

**Table of Contents**

<!-- TOC depthFrom:2 -->

- [GopenPGP V3](#gopenpgp-v3)
  - [GopenPGP V2 support](#gopenpgp-v2-support)
  - [Download/Install](#downloadinstall)
  - [Documentation](#documentation)
  - [Examples](#examples)
    - [Encrypt / Decrypt with a password](#encrypt--decrypt-with-a-password)
    - [Encrypt / Decrypt with PGP keys](#encrypt--decrypt-with-pgp-keys)
    - [Generate key](#generate-key)
    - [Detached and inline signatures](#detached-and-inline-signatures)
    - [Cleartext signed messages](#cleartext-signed-messages)
    - [Encrypt with different outputs](#encrypt-with-different-outputs)
  - [Using with Go Mobile](#using-with-go-mobile)

<!-- /TOC -->

##  GopenPGP V2 support

While GopenPGP V3 introduces a new API with significant enhancements, it is not backward compatible with GopenPGP V2. 
Although we recommend upgrading to V3 for the latest features and improvements, we continue to support GopenPGP V2. 
Our support includes ongoing bug fixes and minor feature updates to ensure stability and functionality for existing users.

GopenPGP V2 can be accessed/modified via the [v2 branch of this repository](https://github.com/ProtonMail/gopenpgp/tree/v2).

## Download/Install

To use GopenPGP with [Go Modules](https://github.com/golang/go/wiki/Modules) just run 
```
go get github.com/ProtonMail/gopenpgp/v3
```
in your project folder.

Then, your code can include it as follows:
```go
package main

import (
	"fmt"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func main() {
	pgp := crypto.PGP()
}
```

## Documentation

A full overview of the API can be found here: https://pkg.go.dev/github.com/ProtonMail/gopenpgp/v3.

## Examples

A file of runnable examples can be found in [crypto_example_test.go](crypto/crypto_example_test.go).

### Encrypt / Decrypt with a password

```go
import "github.com/ProtonMail/gopenpgp/v3/crypto"

password := []byte("hunter2")

pgp := crypto.PGP()
// Encrypt data with a password
encHandle, err := pgp.Encryption().Password(password).New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"))
armored, err := pgpMessage.ArmorBytes()

// Decrypt data with a password
decHandle, err := pgp.Decryption().Password(password).New()
decrypted, err := decHandle.Decrypt(armored, crypto.Armor)
myMessage := decrypted.Bytes()
```

To encrypt with the [latest proposed standard](https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-12.html):
```go
import "github.com/ProtonMail/gopenpgp/v3/profile"

// Use the default crypto refresh profile
pgp := crypto.PGPWithProfile(profile.CryptoRefresh())
// The default crypto refresh profile uses Argon2 for deriving
// session keys and uses an AEAD for encryption (AES-256, OCB mode).
// Encrypt data with password
...
// Decrypt data with password
...
```

Use a custom or preset profile:
```go
import "github.com/ProtonMail/gopenpgp/v3/profile"

// RFC4880 profile
pgp4880 := crypto.PGPWithProfile(profile.RFC4880()) 
// GnuPG profile
gnuPG := crypto.PGPWithProfile(profile.GnuPG())
// Crypto refresh profile
pgpCryptoRefresh := crypto.PGPWithProfile(profile.CryptoRefresh())
```

### Encrypt / Decrypt with PGP keys

```go
// Put keys in backtick (``) to avoid errors caused by spaces or tabs
const pubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`

const privkey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----` // Encrypted private key

const passphrase = []byte(`the passphrase of the private key`) // Passphrase of the privKey
publicKey, err := crypto.NewKeyFromArmored(pubkey)
privateKey, err := crypto.NewPrivateKeyFromArmored(privkey, passphrase)

pgp := crypto.PGP()
// Encrypt plaintext message using a public key
encHandle, err := pgp.Encryption().Recipient(publicKey).New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"))
armored, err := pgpMessage.ArmorBytes()

// Decrypt armored encrypted message using the private key and obtain the plaintext
decHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
decrypted, err := decHandle.Decrypt(armored, crypto.Armor)
myMessage := decrypted.Bytes()

decHandle.ClearPrivateParams()
```

With signatures:
```go
pgp := crypto.PGP()
aliceKeyPriv, err := pgp.KeyGeneration().
  AddUserId("alice", "alice@alice.com").
  New().
  GenerateKey()
aliceKeyPub, err := aliceKeyPriv.ToPublic()

bobKeyPriv, err := pgp.KeyGeneration().
  AddUserId("bob", "bob@bob.com").
  New().
  GenerateKey()
bobKeyPub, err := bobKeyPriv.ToPublic()

// Encrypt and sign plaintext message from alice to bob
encHandle, err := pgp.Encryption().
  Recipient(bobKeyPub).
  SigningKey(aliceKeyPriv).
  New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"))
armored, err := pgpMessage.ArmorBytes()

// Decrypt armored encrypted message using the private key and obtain plain text
decHandle, err := pgp.Decryption().
  DecryptionKey(bobKeyPriv).
  VerificationKey(aliceKeyPub).
  New()
decrypted, err := decHandle.Decrypt(armored, crypto.Armor)
if sigErr := decrypted.SignatureError(); sigErr != nil {
  // Signature verification failed with sigErr
}
myMessage := decrypted.Bytes()

encHandle.ClearPrivateParams()
decHandle.ClearPrivateParams()
```
Encrypt towards multiple recipients:
```go
recipients, err := crypto.NewKeyRing(bobKeyPub)
err = recipients.AddKey(carolKeyPub)
// encrypt plain text message using a public key
encHandle, err := pgp.Encryption().
  Recipients(recipients).
  SigningKey(aliceKeyPriv).
  New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"))
armored, err := pgpMessage.ArmorBytes()

encHandle.ClearPrivateParams()
```

Encrypt towards an (anonymous) recipient:
```go
//...
// The key fingerprint of bob's key is visible in the key packet and
// is included in the signature's intended recipient list.
// The key fingerprint of carols's key is not visible in the key packet ("anonymous" key packet), and
// is not included in the signature's intended recipient list.
encHandle, _ := pgp.Encryption().
  Recipient(bobKeyPub).
  HiddenRecipient(carolKeyPub).
  SigningKey(aliceKeyPriv).
  New()
pgpMessage, _ := encHandle.Encrypt([]byte("my message"))

// Decrypt checks if bobs key fingerprint is in the intended recipient list
// of alice's signature in the message.
decHandleBob, _ := pgp.Decryption().
  DecryptionKey(bobKeyPriv).
  VerificationKey(aliceKeyPub).
  New()
decryptedBob, _ := decHandleBob.Decrypt(pgpMessage.Bytes(), crypto.Bytes)
fmt.Println(string(decryptedBob.Bytes()))

// Disable intended recipient check, there is no info about carols key in the message.
// The decryption function tries all supplied keys for decrypting the "anonymous" key packet.
// If the check is not disabled, the decryption result would contain a signature error.
decHandleCarol, _ := pgp.Decryption().
  DecryptionKey(carolKeyPriv).
  VerificationKey(aliceKeyPub).
  DisableIntendedRecipients().
  New()
decryptedCarol, _ := decHandleCarol.Decrypt(pgpMessage.Bytes(), crypto.Bytes)
```

Encrypt and decrypt large messages with the streaming API:
```go
pgp := crypto.PGP()
// ... See key generation above

// Encrypt plain text stream and write the output to a file
encHandle, err := pgp.Encryption().
  Recipient(bobKeyPub).
  SigningKey(aliceKeyPriv).
  New()
messageReader, err := os.Open("msg.txt")
ciphertextWriter, err := os.Create("out.pgp")

ptWriter, err := encHandle.EncryptingWriter(ciphertextWriter, crypto.Armor)
_, err = io.Copy(ptWriter, messageReader)
err = ptWriter.Close()
err = messageReader.Close()
err = ciphertextWriter.Close()

ctFileRead, err := os.Open("out.pgp")
defer ctFileRead.Close()
// Decrypt stream and read the result to memory
decHandle, err := pgp.Decryption().
  DecryptionKey(bobKeyPriv).
  VerificationKey(aliceKeyPub).
  New()
ptReader, err := decHandle.DecryptingReader(ctFileRead, crypto.Armor)
decResult, err := ptReader.ReadAllAndVerifySignature()
if sigErr := decResult.SignatureError(); sigErr != nil {
  // Handle sigErr
}
// Access decrypted message with decResult.Bytes()
```
### Generate key
Keys are generated with the `GenerateKey` function on the pgp handle.
```go
import "github.com/ProtonMail/gopenpgp/v3/constants"

const (
  name = "Max Mustermann"
  email = "max.mustermann@example.com"
  passphrase = []byte("LongSecret")
)

pgp4880 := crypto.PGPWithProfile(profile.RFC4880())
gnuPG := crypto.PGPWithProfile(profile.GnuPG())
pgpCryptoRefresh := crypto.PGPWithProfile(profile.CryptoRefresh())

// Note that RSA keys should not be generated anymore according to
// draft-ietf-openpgp-crypto-refresh

keyGenHandle := pgp4880.KeyGeneration().AddUserId(name, email).New()
// Generates rsa keys with 3072 bits
rsaKey, err := keyGenHandle.GenerateKey()
// Generates rsa keys with 4092 bits
rsaKeyHigh, err := keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)

keyGenHandle = gnuPG.KeyGeneration().AddUserId(name, email).New()
// Generates curve25519 keys with GnuPG compatibility
ecKey, err := keyGenHandle.GenerateKey()
// Generates curve448 keys with GnuPG compatibility
ecKeyHigh, err := keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)

keyGenHandle = pgpCryptoRefresh.KeyGeneration().AddUserId(name, email).New()
// Generates curve25519 keys with draft-ietf-openpgp-crypto-refresh
ecKey, err = keyGenHandle.GenerateKey()
// Generates curve448 keys with draft-ietf-openpgp-crypto-refresh
ecKeyHigh, err = keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
```

Encrypt (lock) and decrypt (unlock) a secret key:
```go
password := []byte("password")

pgp := crypto.PGP()
// Encrypt key with password
lockedKey, err := pgp.LockKey(aliceKeyPriv, password)
// Decrypt key with password
unlockedKey, err := lockedKey.Unlock(password)
```

### Detached and inline signatures

Sign a plaintext with a private key and verify it with its public key using detached signatures: 

```go
pgp := crypto.PGP()
// ... See generating keys 

signingMessage := []byte("message to sign")

signer, err := pgp.Sign().SigningKey(aliceKeyPriv).Detached().New()
signature, err := signer.Sign(signingMessage, crypto.Armor)

verifier, err := pgp.Verify().VerificationKey(aliceKeyPub).New()
verifyResult, err := verifier.VerifyDetached(signingMessage, signature, crypto.Armor)
if sigErr := verifyResult.SignatureError(); sigErr != nil {
  // Handle sigErr
}

signer.ClearPrivateParams()
```


Sign a plaintext with a private key and verify it with its public key using inline signatures: 

```go
pgp := crypto.PGP()
// ... See generating keys 

signingMessage := []byte("message to sign")

signer, err := pgp.Sign().SigningKey(aliceKeyPriv).New()
signatureMessage, err := signer.Sign(signingMessage, crypto.Armor)

verifier, err := pgp.Verify().VerificationKey(aliceKeyPub).New()
verifyResult, err := verifier.VerifyInline(signatureMessage, crypto.Armor)
if sigErr := verifyResult.SignatureError(); sigErr != nil {
  // Handle sigErr
}
// Access signed data with verifyResult.Bytes()
signer.ClearPrivateParams()
```



### Cleartext signed messages
```go
pgp := crypto.PGP()
// ... See generating keys 

signingMessage := []byte("message to sign")

signer, err := pgp.Sign().SigningKey(aliceKeyPriv).New()
cleartextArmored, err := signer.SignCleartext(signingMessage)
// CleartextArmored has the form:
// -----BEGIN PGP SIGNED MESSAGE-----
// ...
// -----BEGIN PGP SIGNATURE-----
// ...
// -----END PGP SIGNATURE-----

verifier, err := pgp.Verify().VerificationKey(aliceKeyPub).New()
verifyResult, err := verifier.VerifyCleartext(cleartextArmored)
if sigErr := verifyResult.SignatureError(); sigErr != nil {
  // Handle sigErr
}

signer.ClearPrivateParams()
```

### Encrypt with different outputs

Split encrypted message into key packets and data packets 
```go
// Non-streaming
pgpMessage, err := encHandle.Encrypt(...)
keyPackets := pgpMessage.BinaryKeyPacket()
dataPackets := pgpMessage.BinaryDataPacket()

// Streaming 
var keyPackets bytes.Buffer
var dataPackets bytes.Buffer
splitWriter := crypto.NewPGPSplitWriterKeyAndData(&keyPackets, &dataPackets)
ptWriter, _ := encHandle.EncryptingWriter(splitWriter, crypto.Bytes)
// ...
// Key packets are written to keyPackets while data packets are written to dataPackets
```

Produce encrypted detached signatures instead of embedded signatures:
```go
// Non-streaming
encHandle, err := pgp.Encryption().
  Recipient(bobKeyPub).
  SigningKey(aliceKeyPriv).
  DetachedSignature().
  New() // Enable the detached signature option
pgpMessage, err := encHandle.Encrypt(...)
pgpMessageEncSig, err := pgpMessage.EncryptedDetachedSignature()
// pgpMessage.Bytes() encrypted message without an embedded signature
// pgpMessageEncSig.Bytes() encrypted signature message
// pgpMessage:        key packets|enc data packets
// pgpMessageEncSig:  key packets|enc signature packet


// Streaming 
// ...
var encSigDataPackets bytes.Buffer
splitWriter := crypto.NewPGPSplitWriter(&keyPackets, &dataPackets, &encSigDataPackets)
ptWriter, err := encHandle.EncryptingWriter(splitWriter, crypto.Bytes)
// ...
// Key packets are written to keyPackets, data packets are written to dataPackets ,and
// Data packets of the encrypted signature to encSigDataPackets
```

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
