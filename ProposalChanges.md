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
// PlainTextMessage stores an unencrypted text message.
crypto.CleartextMessage struct {
	// The content of the message
	Text string
	// If the decoded message was correctly signed. See constants.SIGNATURE* for all values.
 	Verified int
}
```
or
```
// BinaryMessage stores an unencrypted binary message.
crypto.BinaryMessage struct {
	// The content of the message
	Data []byte
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

## Dropped
### Signature
```
type Signature struct {
	md *openpgp.MessageDetails
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


# API changes
## attachment.go
### AttachmentProcessor
No change.

### EncryptAttachment
Change encryption parameters to messages: either contextual signature with helper or using messages.
```
(pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey *KeyRing) (*models.EncryptedSplit, error):
* (pgp *GopenPGP) EncryptSignAttachmentHelper(publicKey, privateKey, passphrase, fileName string, plainData []byte) (keyPacket, dataPacket, signature []byte, err error)
* (keyRing *KeyRing) EncryptAttachment(message *BinaryMessage, fileName string) (*PGPSplitMessage, error)
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
* (pgp *GopenPGP) DecryptVerifyAttachmentHelper(publicKey, privateKey, passphrase string, keyPacket, dataPacket []byte, armoredSignature string) (plainData []byte, err error)
* (keyRing *KeyRing) DecryptAttachment(message *PGPSplitMessage) (*BinaryMessage, error)
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
No change.

### GenerateKey
No change.

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
* (if plain text) (keyRing *KeyRing) EncryptMessage(message *CleartextMessage, privateKey *KeyRing, trimNewlines bool) (*PGPMessage, error)
* (if binary data) (keyRing *KeyRing) Encrypt(message *BinaryMessage, privateKey *KeyRing) (*PGPMessage, error)
* (if plain text, wrapped) (pgp *GopenPGP) EncryptMessageArmoredHelper(publicKey, plaintext string) (ciphertext string, err error)
* (if plain text, wrapped, signed) (pgp *GopenPGP) EncryptSignMessageArmoredHelper(publicKey, privateKey, passphrase, plaintext string) (ciphertext string, err error)
```
### EncryptCore
Made an internal function.

### EncryptSymmetric
Dropped, now the procedure is split in two parts.
```
(kr *KeyRing) EncryptSymmetric(textToEncrypt string, canonicalizeText bool) (outSplit *models.EncryptedSplit, err error):
* (for encrypting) (keyRing *KeyRing) Encrypt*
* (for splitting) (msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int) (outSplit *PGPSplitMessage, err error)
* (alternative) (keyRing *KeyRing) EncryptAttachment(message *BinaryMessage, fileName string) (*PGPSplitMessage, error)
```

### DecryptString, Decrypt, DecryptArmored
Same as Encrypt*
```
(kr *KeyRing) DecryptString(encrypted string) (SignedString, error):
* (if plain text) (keyRing *KeyRing) DecryptMessage(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*CleartextMessage, error)
* (if binary data) func (keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*BinaryMessage, error)
* (if plain text, wrapped) (pgp *GopenPGP) DecryptMessageArmoredHelper(privateKey, passphrase, ciphertext string) (plaintext string, err error)
* (if plain text, wrapped, verified) (pgp *GopenPGP) DecryptVerifyMessageArmoredHelper(publicKey, privateKey, passphrase, ciphertext string) (plaintext string, err error)
```

### DecryptStringIfNeeded
Replaced with `IsPGPMessage` + `Decrypt*`.
```
(kr *KeyRing) DecryptStringIfNeeded(data string) (decrypted string, err error):
* (pgp *GopenPGP) IsPGPMessage(data string) bool
```

### SignString
Replaced by signing methods.
```
(kr *KeyRing) SignString(message string, canonicalizeText bool) (signed string, err error):
* (keyRing *KeyRing) Sign(message *BinaryMessage) (*BinaryMessage, *PGPSignature, error)
* (keyRing *KeyRing) SignMessage(message *CleartextMessage, trimNewlines bool) (*CleartextMessage, *PGPSignature, error)
```

### DetachedSign
Replaced by signing methods.
```
(kr *KeyRing) DetachedSign(w io.Writer, toSign io.Reader, canonicalizeText bool, armored bool):
* (keyRing *KeyRing) Sign(message *BinaryMessage) (*BinaryMessage, *PGPSignature, error)
* (keyRing *KeyRing) SignMessage(message *CleartextMessage, trimNewlines bool) (*CleartextMessage, *PGPSignature, error)
```

### VerifyString
Same as signing.
```
(kr *KeyRing) VerifyString(message, signature string, sign *KeyRing) (err error):
* (keyRing *KeyRing) Verify(message *BinaryMessage, signature *PGPSignature, verifyTime int64) (*BinaryMessage, error)
* (keyRing *KeyRing) VerifyMessage(message *CleartextMessage, signature *PGPSignature, verifyTime int64) (*CleartextMessage, error)
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
Renamed.
```
(kr *KeyRing) UnmarshalJSON(b []byte) (err error):
* (keyRing *KeyRing) ReadFromJSON(jsonData []byte) (err error)
```

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
(pm *PmCrypto) EncryptMessage(plainText string, publicKey *KeyRing, privateKey *KeyRing, passphrase string, trim bool) (string, error):
* (if plain text) (keyRing *KeyRing) EncryptMessage(message *CleartextMessage, privateKey *KeyRing, trimNewlines bool) (*PGPMessage, error)
* (if binary data) (keyRing *KeyRing) Encrypt(message *BinaryMessage, privateKey *KeyRing) (*PGPMessage, error)
* (if plain text, wrapped) (pgp *GopenPGP) EncryptMessageArmoredHelper(publicKey, plaintext string) (ciphertext string, err error)
* (if plain text, wrapped, signed) (pgp *GopenPGP) EncryptSignMessageArmoredHelper(publicKey, privateKey, passphrase, plaintext string) (ciphertext string, err error)
```

### DecryptMessage, DecryptMessageVerify, DecryptMessageStringKey
See Decrypt*
```
(pm *PmCrypto) DecryptMessage(encryptedText string, privateKey *KeyRing, passphrase string) (string, error):
(pm *PmCrypto) DecryptMessageStringKey(encryptedText string, privateKey string, passphrase string) (string, error):
(pm *PmCrypto) DecryptMessageVerify(encryptedText string, verifierKey *KeyRing, privateKeyRing *KeyRing, passphrase string, verifyTime int64) (*models.DecryptSignedVerify, error) :
* (if plain text) (keyRing *KeyRing) DecryptMessage(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*CleartextMessage, error)
* (if binary data) func (keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*BinaryMessage, error)
* (if plain text, wrapped) (pgp *GopenPGP) DecryptMessageArmoredHelper(privateKey, passphrase, ciphertext string) (plaintext string, err error)
* (if plain text, wrapped, verified) (pgp *GopenPGP) DecryptVerifyMessageArmoredHelper(publicKey, privateKey, passphrase, ciphertext string) (plaintext string, err error)
```

### EncryptMessageWithPassword
The function has been moved to `SymmetricKey` to allow more encryption modes. Previously AES-128 (! not 256 as stated) was used.
```
(pm *PmCrypto) EncryptMessageWithPassword(plainText string, password string) (string, error):
* (if plain text) (simmetricKey *SymmetricKey) EncryptMessage(message *CleartextMessage, trimNewlines bool) (*PGPMessage, error)
* (if binary data) (simmetricKey *SymmetricKey) Encrypt(message *BinaryMessage) (*PGPMessage, error)
* (if plain text, wrapped) (pgp *GopenPGP) EncryptMessageSymmetricHelper(passphrase, plaintext, algo string) (ciphertext string, err error)
* (if plain text, wrapped, AES128) (pgp *GopenPGP) EncryptMessageAES128Helper(passphrase, plaintext string) (ciphertext string, err error)
* (if plain text, wrapped, AES256) (pgp *GopenPGP) EncryptMessageAES256Helper(passphrase, plaintext string) (ciphertext string, err error)
```

### DecryptMessageWithPassword
See `EncryptMessageWithPassword`.
```
(pm *PmCrypto) DecryptMessageWithPassword(encrypted string, password string) (string, error):
* (if plain text) (simmetricKey *SymmetricKey) DecryptMessage(message *PGPMessage) (*CleartextMessage, error)
* (if binary data) (simmetricKey *SymmetricKey) Decrypt(message *PGPMessage) (*BinaryMessage, error)
* (if plain text, wrapped, for all ciphers) (pgp *GopenPGP) DecryptMessageSymmetricHelper(passphrase, ciphertext string) (plaintext string, err error)
```

## mime.go

### DecryptMIMEMessage
Moved to `KeyRing`.
```
(pm *PmCrypto) DecryptMIMEMessage(encryptedText string, verifierKey *KeyRing, privateKeyRing *KeyRing, passphrase string, callbacks MIMECallbacks, verifyTime int64):
* (keyRing *KeyRing) DecryptMIMEMessage(message *PGPMessage, verifyKey *KeyRing, callbacks MIMECallbacks, verifyTime int64)
```

## session.go
### RandomToken, RandomTokenWith
Functions merged, with optional parameter size, in bytes.
```
(pm *PmCrypto) RandomToken() ([]byte, error):
(pm *PmCrypto) RandomTokenWith(size int) ([]byte, error):
* (pgp *GopenPGP) RandomToken(size ...int) ([]byte, error)
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
Moved to `KeyRing`.
```
(pm *PmCrypto) SignTextDetached(plainText string, privateKey *KeyRing, passphrase string, trim bool) (string, error):
* (keyRing *KeyRing) SignMessage(message *CleartextMessage, trimNewlines bool) (*CleartextMessage, *PGPSignature, error)
```

### SignBinDetached
Moved to `KeyRing`.
```
(pm *PmCrypto) SignBinDetached(plainData []byte, privateKey *KeyRing, passphrase string) (string, error):
* (keyRing *KeyRing) Sign(message *BinaryMessage) (*BinaryMessage, *PGPSignature, error)
```

### VerifyTextSignDetachedBinKey
Moved to `KeyRing`.
```
(pm *PmCrypto) VerifyTextSignDetachedBinKey(signature string, plainText string, publicKey *KeyRing, verifyTime int64) (bool, error)
* (keyRing *KeyRing) VerifyMessage(message *CleartextMessage, signature *PGPSignature, verifyTime int64) (*CleartextMessage, error)
```

### VerifyBinSignDetachedBinKey
Moved to `KeyRing`.
```
(pm *PmCrypto) VerifyBinSignDetachedBinKey(signature string, plainData []byte, publicKey *KeyRing, verifyTime int64) (bool, error):
* (keyRing *KeyRing) Verify(message *BinaryMessage, signature *PGPSignature, verifyTime int64) (*BinaryMessage, error)
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
