# Model changes
## Modified
### EncryptedSplit
```
models.EncryptedSplit struct {
	DataPacket []byte
	KeyPacket  []byte
	Algo       string
}
```
is now
```
crypto.PGPSplitMessage struct {
	DataPacket []byte
	KeyPacket  []byte
}
```

### DecryptSignedVerify
```
models.DecryptSignedVerify struct {
	//clear text
	Plaintext string
	//bitmask verify status : 0
	Verify int
	//error message if verify failed
	Message string
}
```
is now
```
// PlainMessage stores an unencrypted text message.
crypto.PlainMessage struct {
	// The content of the message
	Text string
	// If the decoded message was correctly signed. See constants.SIGNATURE* for all values.
 	Verified int
}
```

### pmKeyObject
```
type pmKeyObject struct {
	ID          string
	Version     int
	Flags       int
	Fingerprint string
	PublicKey   string `json:",omitempty"`
	PrivateKey  string
	Primary int
}
```
is now
```
type pgpKeyObject struct {
	ID          string
	Version     int
	Flags       int
	PrivateKey  string
	Primary     int
	Token       string `json:",omitempty"`
	Signature   string `json:",omitempty"`
}
```

### SignedString
```
// SignedString wraps string with Signature
type SignedString struct {
	String string
	Signed *Signature
}
```
is now
```
// ClearTextMessage, split signed clear text message container
type ClearTextMessage struct {
	Data []byte
	Signature []byte
}

```

## Dropped
### Signature
```
type Signature struct {
	md *openpgp.MessageDetails
}
```
## New
### PGPMessage
```
// PGPMessage stores a PGP-encrypted message.
type PGPMessage struct {
	// The content of the message
	Data []byte
}
```

### PGPSignature
```
// PGPSignature stores a PGP-encoded detached signature.
type PGPSignature struct {
	// The content of the message
	Data []byte
}
```

### SignatureVerificationError
```
// SignatureVerificationError is returned from Decrypt and VerifyDetached functions when signature verification fails
type SignatureVerificationError struct {
	Status int
	Message string
}
```


# API changes
## armor.go
### ReadClearSignedMessage
Moved to crypto package. Changed to return ClearTextMessage.
```
ReadClearSignedMessage(signedMessage string) (string, error):
* NewClearTextMessageFromArmored(signedMessage string) (*ClearTextMessage, error)
```
In addition, were added:
```
* NewClearTextMessage(data []byte, signature []byte) *ClearTextMessage
* (msg *ClearTextMessage) GetBinary() []byte
* (msg *ClearTextMessage) GetString() string
* (msg *ClearTextMessage) GetBinarySignature() []byte
* (msg *ClearTextMessage) GetArmored() (string, error)
```

## attachment.go
### AttachmentProcessor
No change.

### EncryptAttachment
Change encryption parameters to messages: either contextual signature with helper or using messages.
```
(pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey *KeyRing) (*models.EncryptedSplit, error):
* (helper) EncryptSignAttachment(publicKey, privateKey, passphrase, fileName string, plainData []byte) (keyPacket, dataPacket, signature []byte, err error)
* (keyRing *KeyRing) EncryptAttachment(message *PlainMessage, fileName string) (*PGPSplitMessage, error)
```

### EncryptAttachmentLowMemory
Renamed.
```
(pm *PmCrypto) EncryptAttachmentLowMemory(estimatedSize int, fileName string, publicKey *KeyRing) (*AttachmentProcessor, error):
* (keyRing *KeyRing) NewLowMemoryAttachmentProcessor(estimatedSize int, fileName string) (*AttachmentProcessor, error)
```

### SplitArmor
Renamed, changed model.
```
SplitArmor(encrypted string) (*models.EncryptedSplit, error):
* NewPGPSplitMessageFromArmored(encrypted string) (*PGPSplitMessage, error)
```

### DecryptAttachment
Same as `EncryptAttachment`.
```
(pm *PmCrypto) DecryptAttachment(keyPacket []byte, dataPacket []byte, kr *KeyRing, passphrase string) ([]byte, error):
* (helper) DecryptVerifyAttachment(publicKey, privateKey, passphrase string, keyPacket, dataPacket []byte, armoredSignature string) (plainData []byte, err error)
* (keyRing *KeyRing) DecryptAttachment(message *PGPSplitMessage) (*PlainMessage, error)
```

## key.go
`SymmetricKey` model and functions have been moved to symmetrickey.go

### DecryptAttKey
Renamed, change to `[]byte` as it's a binary keypacket.
```
DecryptAttKey(kr *KeyRing, keyPacket string) (key *SymmetricKey, err error):
* (keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SymmetricKey, error)
```

### SeparateKeyAndData
This function has been split in two, as it **did not** only separate the data, but when provided a KeyRing decrypt the session key too.
```
SeparateKeyAndData(kr *KeyRing, r io.Reader, estimatedLength int, garbageCollector int) (outSplit *models.EncryptedSplit, err error):
* (for separating key and data) (msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int) (outSplit *PGPSplitMessage, err error)
* (for decrypting SessionKey) (keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SymmetricKey, error)
```

### encodedLength
Dropped as already present in `SeparateKeyAndData` and unused.

### SetKey
Renamed, change to `[]byte` as it's a binary keypacket.
```
SetKey(kr *KeyRing, symKey *SymmetricKey) (packets string, err error):
* (keyRing *KeyRing) EncryptSessionKey(sessionSplit *SymmetricKey) ([]byte, error)
```

### IsKeyExpiredBin
Renamed.
```
(pm *PmCrypto) IsKeyExpiredBin(publicKey []byte) (bool, error):
* (pgp *GopenPGP) IsKeyExpired(publicKey []byte) (bool, error)
```

### IsKeyExpired
Renamed.
```
(pm *PmCrypto) IsKeyExpired(publicKey string) (bool, error):
* (pgp *GopenPGP) IsArmoredKeyExpired(publicKey string) (bool, error)
```

### GenerateRSAKeyWithPrimes
`userName` and `domain` joined in `email`.
Added `name` parameter.
To emulate the old behaviour `name = email = userName + "@" + domain`.
```
(pm *PmCrypto) GenerateRSAKeyWithPrimes(userName, domain, passphrase, keyType string, bits int, prime1, prime2, prime3, prime4 []byte) (string, error):
* (pgp *GopenPGP) GenerateRSAKeyWithPrimes(name, email, passphrase, keyType string, bits int, prime1, prime2, prime3, prime4 []byte) (string, error):
```

### GenerateKey
`userName` and `domain` joined in `email`.
Added `name` parameter.
To emulate the old behaviour `name = email = userName + "@" + domain`.
```
(pm *PmCrypto) GenerateKey(userName, domain, passphrase, keyType string, bits int) (string, error) :
* (pgp *GopenPGP) GenerateKey(name, email, passphrase, keyType string, bits int) (string, error):
```

### UpdatePrivateKeyPassphrase
No change.

### CheckKey
Renamed.
```
(pm *PmCrypto) CheckKey(pubKey string) (string, error):
* (pgp *GopenPGP) PrintFingerprints(pubKey string) (string, error)
```

## keyring.go
### Signature.KeyRing
Dropped with signature.

### Signature.IsBy
Dropped with signature.

### GetEntities
No change.

### GetSigningEntity
KeyRings must be already unlocked when provided to encrypt/decrypt/sign/verify functions.
```
(kr *KeyRing) GetSigningEntity(passphrase string) *openpgp.Entity:
* (keyRing *KeyRing) GetSigningEntity() (*openpgp.Entity, error)
```

### Encrypt, EncryptArmored, EncryptString
This function has been divided in different sub-functions and wrappers have been provided for the key unlock and message models.
```
(kr *KeyRing) Encrypt(w io.Writer, sign *KeyRing, filename string, canonicalizeText bool) (io.WriteCloser, error):
* (if binary data) (keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error)
* (if plain text, wrapped) (helper) EncryptMessageArmored(publicKey, plaintext string) (ciphertext string, err error)
* (if plain text, wrapped, signed) (helper) EncryptSignMessageArmored(publicKey, privateKey, passphrase, plaintext string) (ciphertext string, err error)
```
### EncryptCore
Made an internal function.

### EncryptSymmetric
Dropped, now the procedure is split in two parts.
```
(kr *KeyRing) EncryptSymmetric(textToEncrypt string, canonicalizeText bool) (outSplit *models.EncryptedSplit, err error):
* (for encrypting) (keyRing *KeyRing) Encrypt*
* (for splitting) (msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int) (outSplit *PGPSplitMessage, err error)
* (alternative) (keyRing *KeyRing) EncryptAttachment(message *PlainMessage, fileName string) (*PGPSplitMessage, error)
```

### DecryptString, Decrypt, DecryptArmored
Same as Encrypt*. If signature verification fails it will return a SignatureVerificationError.
```
(kr *KeyRing) DecryptString(encrypted string) (SignedString, error):
* (if binary data) func (keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*PlainMessage, error)
* (if plain text, wrapped) (helper) DecryptMessageArmored(privateKey, passphrase, ciphertext string) (plaintext string, err error)
* (if plain text, wrapped, verified) (helper) DecryptVerifyMessageArmored(publicKey, privateKey, passphrase, ciphertext string) (plaintext string, err error)
```

### DecryptStringIfNeeded
Replaced with `IsPGPMessage` + `Decrypt*`.
```
(kr *KeyRing) DecryptStringIfNeeded(data string) (decrypted string, err error):
* (pgp *GopenPGP) IsPGPMessage(data string) bool
```

### SignString, DetachedSign
Replaced by signing methods.
```
(kr *KeyRing) SignString(message string, canonicalizeText bool) (signed string, err error):
(kr *KeyRing) DetachedSign(w io.Writer, toSign io.Reader, canonicalizeText bool, armored bool):
* (keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error)
```

### VerifyString
Same as signing. Returns SignatureVerificationError if the verification fails.
```
(kr *KeyRing) VerifyString(message, signature string, sign *KeyRing) (err error):
* (to verify) (keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) error
```

### Unlock
No change. Added:
```
(keyRing *KeyRing) UnlockWithPassphrase(passphrase string) error
```

### WriteArmoredPublicKey
No change.

### ArmoredPublicKeyString
Renamed.
```
(kr *KeyRing) ArmoredPublicKeyString() (s string, err error):
* (keyRing *KeyRing) GetArmoredPublicKey() (s string, err error)
```

### BuildKeyRing
No change.

### BuildKeyRingNoError
No change.

### BuildKeyRingArmored
No change.

### UnmarshalJSON
No change.

### Identities
No change

### KeyIds
No change.

### ReadArmoredKeyRing
No change.

### ReadKeyRing
No change.

### FilterExpiredKeys
No change.

## message.go
Many functions are duplicates of keyring.go

### EncryptMessage
See Encrypt*
```
(pm *PmCrypto) EncryptMessage(plaintext string, publicKey *KeyRing, privateKey *KeyRing, passphrase string, trim bool) (string, error):
* (if binary data) (keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error)
* (if plain text, wrapped) (helper) EncryptMessageArmored(publicKey, plaintext string) (ciphertext string, err error)
* (if plain text, wrapped, signed) (helper) EncryptSignMessageArmored(publicKey, privateKey, passphrase, plaintext string) (ciphertext string, err error)
```

### DecryptMessage, DecryptMessageVerify, DecryptMessageStringKey
See Decrypt*
```
(pm *PmCrypto) DecryptMessage(encryptedText string, privateKey *KeyRing, passphrase string) (string, error):
(pm *PmCrypto) DecryptMessageStringKey(encryptedText string, privateKey string, passphrase string) (string, error):
(pm *PmCrypto) DecryptMessageVerify(encryptedText string, verifierKey *KeyRing, privateKeyRing *KeyRing, passphrase string, verifyTime int64) (*models.DecryptSignedVerify, error) :
* (if binary data) (keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*PlainMessage, error)
* (if plain text, wrapped) (helper) DecryptMessageArmored(privateKey, passphrase, ciphertext string) (plaintext string, err error)
* (if plain text, wrapped, verified) (helper) DecryptVerifyMessageArmored(publicKey, privateKey, passphrase, ciphertext string) (plaintext string, err error)
```

### EncryptMessageWithPassword
The function has been renamed and moved to `SymmetricKey` to allow more encryption modes. Previously AES-128 (! not 256 as stated) was used.
```
(pm *PmCrypto) EncryptMessageWithPassword(plaintext string, password string) (string, error):
* (if binary data) (symmetricKey *SymmetricKey) Encrypt(message *PlainMessage) (*PGPMessage, error)
* (if plain text, wrapped) (helper) EncryptMessageWithToken(token, plaintext string) (ciphertext string, err error)
* (if plain text, wrapped) (helper) EncryptMessageWithTokenAlgo(token, plaintext, algo string) (ciphertext string, err error)
```

### DecryptMessageWithPassword
See `EncryptMessageWithPassword`.
```
(pm *PmCrypto) DecryptMessageWithPassword(encrypted string, password string) (string, error):
* (if binary data) (symmetricKey *SymmetricKey) Decrypt(message *PGPMessage) (*PlainMessage, error)
* (if plain text, wrapped, for all ciphers) (helper) DecryptMessageWithToken(token, ciphertext string) (plaintext string, err error)
```

## mime.go

### DecryptMIMEMessage
Moved to `KeyRing`.
```
(pm *PmCrypto) DecryptMIMEMessage(encryptedText string, verifierKey *KeyRing, privateKeyRing *KeyRing, passphrase string, callbacks MIMECallbacks, verifyTime int64):
* (keyRing *KeyRing) DecryptMIMEMessage(message *PGPMessage, verifyKey *KeyRing, callbacks MIMECallbacks, verifyTime int64)
```

## session.go
### RandomToken
No change.

### RandomTokenWith
Renamed.
```
(pm *PmCrypto) RandomTokenWith(size int) ([]byte, error):
* (pgp *GopenPGP) RandomTokenSize(size int) ([]byte, error)
```

### GetSessionFromKeyPacket
Dropped, use now `DecryptSessionKey`.
```
(pm *PmCrypto) GetSessionFromKeyPacket(keyPackage []byte, privateKey *KeyRing, passphrase string) (*SymmetricKey, error):
* (keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SymmetricKey, error)
```

### KeyPacketWithPublicKey, KeyPacketWithPublicKeyBin
Dropped, use now `EncryptSessionKey`.
```
(pm *PmCrypto) KeyPacketWithPublicKey(sessionSplit *SymmetricKey, publicKey string) ([]byte, error):
(pm *PmCrypto) KeyPacketWithPublicKeyBin(sessionSplit *SymmetricKey, publicKey []byte) ([]byte, error):
* (keyRing *KeyRing) EncryptSessionKey(sessionSplit *SymmetricKey) ([]byte, error)
```

### GetSessionFromSymmetricPacket
Renamed, moved to `SymmetricKey`.
```
(pm *PmCrypto) GetSessionFromSymmetricPacket(keyPackage []byte, password string) (*SymmetricKey, error):
* NewSymmetricKeyFromKeyPacket(keyPacket []byte, password string) (*SymmetricKey, error)
```

### SymmetricKeyPacketWithPassword
Renamed, moved to `SymmetricKey`.
```
(pm *PmCrypto) SymmetricKeyPacketWithPassword(sessionSplit *SymmetricKey, password string) ([]byte, error):
* (symmetricKey *SymmetricKey) EncryptToKeyPacket(password string) ([]byte, error)
```

## sign_detached.go

### SignTextDetached
Moved to `KeyRing`, changed to `Sign`.
```
(pm *PmCrypto) SignTextDetached(plaintext string, privateKey *KeyRing, passphrase string, trim bool) (string, error):
* (if just signature) (keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error)
* (if PGP SIGNED MESSAGE) (helper) SignCleartextMessage(keyRing *crypto.KeyRing, text string) (string, error)
* (if PGP SIGNED MESSAGE) (helper) SignCleartextMessageArmored(privateKey, passphrase, text string) (string, error)
```

### SignBinDetached
Moved to `KeyRing`.
```
(pm *PmCrypto) SignBinDetached(plainData []byte, privateKey *KeyRing, passphrase string) (string, error):
* (keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error)
```

### VerifyTextSignDetachedBinKey, VerifyBinSignDetachedBinKey
Moved to `KeyRing`, changed to Verify.
See signature_test.go for use examples.
```
(pm *PmCrypto) VerifyTextSignDetachedBinKey(signature string, plaintext string, publicKey *KeyRing, verifyTime int64) (bool, error):
(pm *PmCrypto) VerifyBinSignDetachedBinKey(signature string, plainData []byte, publicKey *KeyRing, verifyTime int64) (bool, error):
* (to verify) (keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) (error)
* (if PGP SIGNED MESSAGE) (helper) VerifyCleartextMessage(keyRing *crypto.KeyRing, armored string, verifyTime int64) (string, error)
* (if PGP SIGNED MESSAGE) (helper) VerifyCleartextMessageArmored(publicKey, armored string, verifyTime int64) (string, error)
```

## signature_collector.go
No change.

## time.go
### UpdateTime
No change.

### GetTimeUnix
Renamed.
```
(pm *PmCrypto) GetTimeUnix() int64:
(pm *PmCrypto) GetUnixTime() int64
```

### GetTime
No change.
