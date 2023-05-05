# GopenPGP V3
[![Build Status](https://travis-ci.org/ProtonMail/gopenpgp.svg?branch=master)](https://travis-ci.org/ProtonMail/gopenpgp)

GopenPGP V3 is a high-level OpenPGP library built on top of [a fork of the golang
crypto library](https://github.com/lubux/go-crypto/tree/version-2).

**Table of Contents**

<!-- TOC depthFrom:2 -->

- [GopenPGP V3](#gopenpgp-v3)
  - [Examples](#examples)
    - [Encrypt / Decrypt with password](#encrypt--decrypt-with-password)
    - [Encrypt / Decrypt with PGP keys](#encrypt--decrypt-with-pgp-keys)
    - [Generate key](#generate-key)
    - [Detached and inline signatures](#detached-and-inline-signatures)
    - [Cleartext signed messages](#cleartext-signed-messages)
    - [Encrypt with different outputs](#encrypt-with-different-outputs)

<!-- /TOC -->

## Examples

### Encrypt / Decrypt with password

```go
import "github.com/ProtonMail/gopenpgp/v3/crypto"

password := []byte("hunter2")

pgp := crypto.PGP()
// Encrypt data with password
encHandle, err := pgp.Encryption().Password(password).New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"), nil)
armored, err := pgpMessage.GetArmored()

// Decrypt data with password
decHandle, err := pgp.Decryption().Password(password).Armored().New()
decrypted, err := decHandle.Decrypt([]byte(armored))
myMessage := decrypted.Result()
```

To encrypt with the new algorithms from the crypto refresh:
```go
// Use the default crypto refresh profile
pgp := crypto.PGPWithProfile(profile.CryptoRefresh()) // or crypto.PGPCryptoRefresh()
// The default crypto refresh profile uses Argon2 for deriving
// session keys and uses an AEAD for encryption (AES-256, OCB mode).
// Encrypt data with password
...
// Decrypt data with password
...
```

Use custom or preset profile:
```go
// RFC4880 profile
pgp4880 := crypto.PGPWithProfile(profile.RFC4880()) 
// Draft-koch profile
pgpKoch := crypto.PGPWithProfile(profile.Koch())
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

pgp := crypto.PGP() // For v6 crypto.PGPCryptoRefresh()
// Encrypt plaintext message using a public key
encHandle, err := pgp.Encryption().Recipient(publicKey).
New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"), nil)
armored, err := pgpMessage.GetArmored()

// Decrypt armored encrypted message using the private key and obtain the plaintext
decHandle, err := pgp.Decryption().DecryptionKey(privateKey).Armored().
New()
decrypted, err := decHandle.Decrypt([]byte(armored))
myMessage := decrypted.Result()

decHandle.ClearPrivateParams()
```

With signatures:
```go
pgp := crypto.PGP() // crypto.PGPCryptoRefresh()
aliceKeyPriv, err := pgp.GenerateKey("alice", "alice@alice.com", constants.Standard)
aliceKeyPub, err := aliceKeyPriv.ToPublic()

bobKeyPriv, err := pgp.GenerateKey("bob", "bob@bob.com", constants.Standard)
bobKeyPub, err := bobKeyPriv.ToPublic()

// Encrypt plaintext message from alice to bob
encHandle, err := pgp.Encryption().
  Recipient(bobKeyPub).
  SigningKey(aliceKeyPriv).
  New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"), nil)
armored, err := pgpMessage.GetArmored()

// Decrypt armored encrypted message using the private key and obtain plain text
decHandle, err := pgp.Decryption().
  DecryptionKey(bobKeyPriv).
  VerifyKey(aliceKeyPub).
  Armored().
  New()
decrypted, err := decHandle.Decrypt([]byte(armored))
if decrypted.HasSignatureError() {
  // Signature verification failed with decrypted.SignatureError()
}
myMessage := decrypted.Result()

encHandle.ClearPrivateParams()
decHandle.ClearPrivateParams()
```
Encrypt towards multiple recipients:
```go
recipients, err := crypto.NewKeyRing(bobKeyPub)
err = recipients.AddKey(carolKeyPub)
// encrypt plain text message using public key
encHandle, err := pgp.Encryption().
  Recipients(recipients).
  SigningKey(aliceKeyPriv).
  New()
pgpMessage, err := encHandle.Encrypt([]byte("my message"), nil)
armored, err := pgpMessage.GetArmored()

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
pgpMessage, _ := encHandle.Encrypt([]byte("my message"), nil)

// Decrypt checks if bobs key fingerprint is in the intended recipient list
// of alice's signature in the message.
decHandleBob, _ := pgp.Decryption().
  DecryptionKey(bobKeyPriv).
  VerifyKey(aliceKeyPub).
  New()
decryptedBob, _ := decHandleBob.Decrypt(pgpMessage.GetBinary())
fmt.Println(string(decryptedBob.Result()))

// Disable intended recipient check, there is no info about carols key in the message.
// The decryption function tries all supplied keys for decrypting the "anonymous" key packet.
// If the check is not disabled, the decryption result would contain a signature error.
decHandleCarol, _ := pgp.Decryption().
  DecryptionKey(carolKeyPriv).
  VerifyKey(aliceKeyPub).
  DisableIntendedRecipients().
  New()
decryptedCarol, _ := decHandleCarol.Decrypt(pgpMessage.GetBinary())
```

Encrypt and decrypt large messages with the streaming API:
```go
pgp := crypto.PGP() // For the crypto refresh crypto.PGPCryptoRefresh()
// ... See key generation above

// Encrypt plain text stream and write the output to a file
encHandle, err := pgp.Encryption().
  Recipient(bobKeyPub).
  SigningKey(aliceKeyPriv).
  Armor().
  New()
messageReader, err := os.Open("msg.txt")
ciphertextWriter, err := os.Create("out.pgp")

ptWriter, err := encHandle.EncryptingWriter(ciphertextWriter, nil)
_, err = io.Copy(ptWriter, messageReader)
err = ptWriter.Close()
err = messageReader.Close()
err = ciphertextWriter.Close()

ctFileRead, err := os.Open("out.pgp")
defer ctFileRead.Close()
// Decrypt stream and read the result to memory
decHandle, err := pgp.Decryption().
  DecryptionKey(bobKeyPriv).
  VerifyKey(aliceKeyPub).
  Armored().
  New()
ptReader, err := decHandle.DecryptingReader(ctFileRead)
decResult, err := ptReader.ReadAllAndVerifySignature()
if decResult.HasSignatureError() {
  // Handle decResult.SignatureError() error
}
// Access decrypted message with decResult.Result()
```
### Generate key
Keys are generated with the `GenerateKey` function on the pgp handle.
```go
const (
  name = "Max Mustermann"
  email = "max.mustermann@example.com"
  passphrase = []byte("LongSecret")
)

pgp4880 := crypto.PGPWithProfile(profile.RFC4880())
pgpKoch := crypto.PGPWithProfile(profile.Koch())
pgpCryptoRefresh := crypto.PGPWithProfile(profile.CryptoRefresh())

// Note that RSA keys should not be generated anymore according to
// draft-ietf-openpgp-crypto-refresh

// Generates rsa keys with 3072 bits
rsaKey, err := pgp.GenerateKey(name, email, constants.Standard)
// Generates rsa keys with 4092 bits
rsaKeyHigh, err := pgp.GenerateKey(name, email, constants.High)

// Generates curve25519 keys with draft-koch-openpgp-2015-rfc4880bis-01
ecKey, err := pgpKoch.GenerateKey(name, email, constants.Standard)
// Generates curve448 keys with draft-koch-openpgp-2015-rfc4880bis-01
ecKeyHigh, err := pgpKoch.GenerateKey(name, email, constants.High)

// Generates curve25519 keys with draft-ietf-openpgp-crypto-refresh
ecKey, err := pgpCryptoRefresh.GenerateKey(name, email, constants.Standard)
// Generates curve448 keys with draft-ietf-openpgp-crypto-refresh
ecKeyHigh, err := pgpCryptoRefresh.GenerateKey(name, email, constants.High)
```

Encrypt (lock) and decrypt (unlock) a secret key:
```go
password := []byte("password")

pgp := crypto.PGP() // crypto.PGPCryptoRefresh()
aliceKeyPriv, err := pgp.GenerateKey("alice", "alice@alice.com", constants.Standard)

// Encrypt key with password
lockedKey, err := pgp.LockKey(aliceKeyPriv, password)
// Decrypt key with password
unlockedKey, err := lockedKey.Unlock(password)
```

### Detached and inline signatures

Sign a plaintext with a private key and verify it with its public key using detached signatures: 

```go
pgp := crypto.PGP() // crypto.PGPCryptoRefresh()
// ... See generating keys 

signingMessage := []byte("message to sign")

signer, err := pgp.Sign().SigningKey(aliceKeyPriv).Detached().
New()
signature, err := signer.Sign(signingMessage, nil)

verifier, err := pgp.Verify().VerifyKey(aliceKeyPub).
New()
verifyResult, err := verifier.Verify(signingMessage, signature)
if verifyResult.HasSignatureError() {
  // Handle verifyResult.SignatureError()
}

signer.ClearPrivateParams()
```


Sign a plaintext with a private key and verify it with its public key using inline signatures: 

```go
pgp := crypto.PGP() // crypto.PGPCryptoRefresh()
// ... See generating keys 

signingMessage := []byte("message to sign")

signer, err := pgp.Sign().SigningKey(aliceKeyPriv).
New()
signatureMessage, err := signer.Sign(signingMessage, nil)

verifier, err := pgp.Verify().VerifyKey(aliceKeyPub).
New()
verifyResult, err := verifier.Verify(nil, signatureMessage)
if verifyResult.HasSignatureError() {
  // Handle verifyResult.SignatureError()
}

signer.ClearPrivateParams()
```



### Cleartext signed messages
```go
pgp := crypto.PGP() // For the crypto refresh crypto.PGPCryptoRefresh()
// ... See generating keys 

signingMessage := []byte("message to sign")

signer, err := pgp.Sign().SigningKey(aliceKeyPriv).
New()
cleartextArmored, err := signer.SignCleartext(signingMessage)
// CleartextArmored has the form:
// -----BEGIN PGP SIGNED MESSAGE-----
// ...
// -----BEGIN PGP SIGNATURE-----
// ...
// -----END PGP SIGNATURE-----

verifier, err := pgp.Verify().VerifyKey(aliceKeyPub).
New()
verifyResult, err := verifier.VerifyCleartext(cleartextArmored)
if verifyResult.HasSignatureError() {
  // Handle verifyResult.SignatureError()
}

signer.ClearPrivateParams()
```

### Encrypt with different outputs

Split encrypted message into key packets and data packets 
```go
// Non-streaming
pgpMessage, err := encHandle.Encrypt(...)
keyPackets := pgpMessage.GetBinaryKeyPacket()
dataPackets := pgpMessage.GetBinaryDataPacket()

// Streaming 
var keyPackets bytes.Buffer
var dataPackets bytes.Buffer
splitWriter := crypto.NewPGPMessageWriterSplit(&keyPackets, &dataPackets)
ptWriter, _ := encHandle.EncryptingWriter(splitWriter, nil)
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
pgpMessageEncSig, err := pgpMessage.GetEncryptedDetachedSignature()
// pgpMessage.GetBinary() encrypted message without an embedded signature
// pgpMessageEncSig.GetBinary() encrypted signature message
// pgpMessage:        key packets|enc data packets
// pgpMessageEncSig:  key packets|enc signature packet


// Streaming 
// ...
var encSigDataPackets bytes.Buffer
splitWriter := crypto.NewPGPMessageWriter(&keyPackets, &dataPackets, &encSigDataPackets)
ptWriter, err := encHandle.EncryptingWriter(splitWriter, nil)
// ...
// Key packets are written to keyPackets, data packets are written to dataPackets ,and
// Data packets of the encrypted signature to encSigDataPackets
```
