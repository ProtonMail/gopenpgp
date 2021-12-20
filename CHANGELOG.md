# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Function to verify a detached signature and get it's creation time: 
```go
func (keyRing *KeyRing) GetVerifiedSignatureTimestamp(message *PlainMessage, signature *PGPSignature, verifyTime int64) (int64, error)
```

## [2.3.1] 2021-12-15
### Fixed
- Fix the verification of PGP/MIME message signatures:
	- Improve the handling of the dual verification status so that it is considered invalid if both embedded and PGP/MIME signatures are invalid.
	- start calling `callback.OnVerified(status int)` to communicate the status verification of the message.

## [2.3.0] 2021-11-15
### Added
- `Key.IsRevoked()` to check the revocation status of a key
### Security
- Upgraded underlying crypto library to fix handling of revoked keys

## [2.2.5] 2021-11-11
### Fixed
- Protect the global `pgp` variable fields with a lock.
- Unlock and lock dummy keys correctly

## [2.2.4] 2021-09-29
### Fixed
- Use the provided `verifyTime` instead of the current time when verifying embedded signatures.

## [2.2.3] 2021-09-21
### Changed
- Keys are now generated with ZLIB as preferred compression algorithm
- Upgraded underlying crypto library

## [2.2.2] 2021-08-04
### Added
- `NewKeyFromEntity` to create a key from an openpgp entity

### Changed
- Improved documentation for differences between text and binary messages

### Deprecated
- `(key *Key) Check() (bool, error)` is now deprecated, all keys are now checked upon import from x/crypto

### Fixed
- Dummy keys now show the correct locked/unlocked status

### Security
- All keys are now checked on parsing from the underlying library

## [2.2.1] 2021-07-27
### Changed
- Changed the returned `SignatureVerificationError.Status` when trying to verify a message with no embedded signature. It used to return `constants.SIGNATURE_NO_VERIFIER` and now returns `constants.SIGNATURE_NOT_SIGNED`.
This change impacts : 
	- `func (sk *SessionKey) DecryptAndVerify(...)`
	- `func (msg *PlainMessageReader) VerifySignature(...)`
	- `func (keyRing *KeyRing) Decrypt(...)`
- Improved error messages for failures in password protected message decryption

### Added 
- Helper to access the SignatureVerificationError explicitly when decrypting streams  in mobile apps: 
	```go
	func VerifySignatureExplicit(
		reader *crypto.PlainMessageReader,
	) (signatureVerificationError *crypto.SignatureVerificationError, err error)
	```

## [2.2.0] 2021-06-30
### Added
- Streaming API:
	- New structs:
		- `PlainMessageMetadata`: holds the metadata of a plain PGP message
			```go
			type PlainMessageMetadata struct {
				IsBinary bool
				Filename string
				ModTime  int64
			}
			```
		- `PlainMessageReader` implements `Reader` and:
			```go
			func (msg *PlainMessageReader) GetMetadata() *PlainMessageMetadata
			func (msg *PlainMessageReader) VerifySignature() (err error)
			```
		- `EncryptSplitResult` implements `WriteCloser` and:
			```go
			func (res *EncryptSplitResult) GetKeyPacket() (keyPacket []byte, err error)
			```
	- Keyring methods:
		- Encrypt (and optionally sign) a message directly into a `Writer`:
			```go
			func (keyRing *KeyRing) EncryptStream(
				pgpMessageWriter Writer,
				plainMessageMetadata *PlainMessageMetadata,
				signKeyRing *KeyRing,
			) (plainMessageWriter WriteCloser, err error)
			```
		- Encrypt (and optionally sign) a message directly into a `Writer` (split keypacket and datapacket):
			```go
			func (keyRing *KeyRing) EncryptSplitStream(
				dataPacketWriter Writer,
				plainMessageMetadata *PlainMessageMetadata,
				signKeyRing *KeyRing,
			) (*EncryptSplitResult, error)
			```
	
		- Decrypt (and optionally verify) a message from a `Reader`:
			```go
			func (keyRing *KeyRing) DecryptStream(
				message Reader,
				verifyKeyRing *KeyRing,
				verifyTime int64,
			) (plainMessage *PlainMessageReader, err error)
			```
			N.B.: to verify the signature, you will need to call `plainMessage.VerifySignature()` after all the data has been read from `plainMessage`.
		- Decrypt (and optionally verify) a split message, getting the datapacket from a `Reader`:
			```go
			func (keyRing *KeyRing) DecryptSplitStream(
				keypacket []byte,
				dataPacketReader Reader,
				verifyKeyRing *KeyRing, verifyTime int64,
			) (plainMessage *PlainMessageReader, err error)
			```
			N.B.: to verify the signature, you will need to call `plainMessage.VerifySignature()` after all the data has been read from `plainMessage`.
		- Generate a detached signature from a `Reader`:
			```go
			func (keyRing *KeyRing) SignDetachedStream(message Reader) (*PGPSignature, error)
			```
		- Verify a detached signature for a `Reader`:
			```go
			func (keyRing *KeyRing) VerifyDetachedStream(
				message Reader,
				signature *PGPSignature,
				verifyTime int64,
			) error
			```
		- Generate an encrypted detached signature from a `Reader`:
			```go
			func (keyRing *KeyRing) SignDetachedEncryptedStream(
				message Reader,
				encryptionKeyRing *KeyRing,
			) (encryptedSignature *PGPMessage, err error)
			```
		- Verify an encrypted detached signature for a `Reader`:
			```go
			func (keyRing *KeyRing) VerifyDetachedEncryptedStream(
				message Reader,
				encryptedSignature *PGPMessage,
				decryptionKeyRing *KeyRing,
				verifyTime int64,
			) error
			```
	- SessionKey methods:
		- Encrypt (and optionally sign) a message into a `Writer`:
			```go
			func (sk *SessionKey) EncryptStream(
				dataPacketWriter Writer,
				plainMessageMetadata *PlainMessageMetadata,
				signKeyRing *KeyRing,
			) (plainMessageWriter WriteCloser, err error)
			```
		- Decrypt (and optionally verify) a message from a `Reader`:
			```go
			func (sk *SessionKey) DecryptStream(
				dataPacketReader Reader,
				verifyKeyRing *KeyRing,
				verifyTime int64,
			) (plainMessage *PlainMessageReader, err error)
			```
			N.B.: to verify the signature, you will need to call `plainMessage.VerifySignature()` after all the data has been read from `plainMessage`.
	- Mobile apps helpers for `Reader` and `Writer`: 
		Due to limitations of `gomobile`, mobile apps can't implement the `Reader` and `Writer` interfaces directly.
		
		- Implementing `Reader`: Apps should implement the interface:
			```go
			type MobileReader interface {
				Read(max int) (result *MobileReadResult, err error)
			}
			type MobileReadResult struct {
				N     int    // N, The number of bytes read
				IsEOF bool   // IsEOF, If true, then the reader has reached the end of the data to read.
				Data  []byte // Data, the data that has been read
			}
			```
			And then wrap it with `Mobile2GoReader(mobileReader)` to turn it into a `Reader`.

		- Implementing `Writer`:
		
			The apps should implement the `Writer` interface directly, but still need to wrap the writer with `Mobile2GoWriter(mobileWriter)`. We also provide the `Mobile2GoWriterWithSHA256` if you want to compute the SHA256 hash of the written data.

		- Using a `Reader`: To use a reader returned by golang in mobile apps: you should wrap it with:
			- Android: `Go2AndroidReader(reader)`, implements the `Reader` interface, but returns `n == -1` instead of `err == io.EOF`
			- iOS: `Go2IOSReader(reader)`, implements `MobileReader`.
		- Using a `Writer`: you can use a writer returned by golang directly.

## [2.1.10] 2021-06-16
### Fixed
- Removed time interpolation via monotonic clock that can cause signatures in the future

## [2.1.9] 2021-05-12
### Changed
- Updated the underlying crypto library

## [2.1.8] 2021-04-27
### Added
- Key and KeyRing methods to check if a key/keyring can Encrypt or Verify
```go
(key *Key) CanVerify() bool
(key *Key) CanEncrypt() bool
(keyRing *KeyRing) CanVerify() bool
(keyRing *KeyRing) CanEncrypt() bool
```
- SessionKey methods to encrypt/decrypt and simultaneously sign/verify with an asymmetric key (embedded signature)
```go
(sk *SessionKey) EncryptAndSign(message *PlainMessage, signKeyRing *KeyRing) ([]byte, error)
(sk *SessionKey) DecryptAndVerify(dataPacket []byte, verifyKeyRing *KeyRing, verifyTime int64) (*PlainMessage, error)
```
- The mobile helper `DecryptSessionKeyExplicitVerify` to allow using session key decryption + verification operations via gomobile  

## [2.1.7] 2021-03-30

### Added 
- `ManualAttachmentProcessor`: a new kind of attachment processor where the caller has to first allocate a buffer large enough for the whole data packet to be written to. It can be created with 
```processor, err := keyRing.NewManualAttachmentProcessor(estimatedSize, filename, dataBuffer)```.

### Fixed
- Fix random failure in AES tests

### Changed
- Updated the x/mobile fork and the build script to work with golang 1.16

## [2.1.6] 2021-03-17
### Added
- Decryption tests for attachments

### Fixed
- Armoring headers for public or private keys
- Session key decoding on invalid keys
- Support for multiple embedded signatures (not nested)

### Security
- Updated the underlying crypto library

## [2.1.5] 2021-02-19

## Changed
- Removed an unnecessary cloning in the attachment processor, to perform better in low memory settings

## [2.1.4] 2021-01-08
### Added
- Methods for generating an verifying encrypted detached signatures
```go
(signingKeyRing *KeyRing) SignDetachedEncrypted(message *PlainMessage, encryptionKeyRing *KeyRing) (encryptedSignature *PGPMessage, err error)
(verifyingKeyRing *KeyRing) VerifyDetachedEncrypted(message *PlainMessage, encryptedSignature *PGPMessage, decryptionKeyRing *KeyRing, verifyTime int64) error
```

## [2.1.3] 2020-12-09
### Added
- `helper.FreeOSMemory()` to explicitly call the GC and release the memory to the OS

### Changed
- Users of the library no longer need a `replace` directive for x/crypto
- Added new calls to `runtime.GC()` in the low memory attachment processor
- Reduced attachment memory allocation

## [2.1.2] 2020-12-01
### Added
- `SetKeyGenerationOffset` to add an offset in key generation time and prevent not-yet-valid keys.

### Changed
- Improved canonicalization performance

## [2.1.1] 2020-11-16
### Changed
- Session key decryption now considers multiple key packets 
### Fixed
- Improved key parsing error handling

## [2.1.0] 2020-11-04
### Security
- Updated underlying crypto library

### Added
- Key Armoring with custom headers
```go
(key *Key) ArmorWithCustomHeaders(comment, version string) (string, error)
(key *Key) GetArmoredPublicKeyWithCustomHeaders(comment, version string) (string, error)
```

- Message armoring with custom headers
```go
(msg *PGPMessage) GetArmoredWithCustomHeaders(comment, version string) (string, error)
```

- Extraction of encryption key IDs from a PGP message, i.e. the IDs of the keys used in the encryption of the session key
```go
(msg *PGPMessage) GetEncryptionKeyIDs() ([]uint64, bool)
(msg *PGPMessage) GetHexEncryptionKeyIDs() ([]uint64, bool)
```

- Extraction of signing key IDs from a PGP message, i.e. the IDs of the keys used in the signature of the message 
    (of all the readable, unencrypted signature packets)
```go
(msg *PGPMessage) GetSignatureKeyIDs() ([]uint64, bool)
(msg *PGPMessage) GetHexSignatureKeyIDs() ([]string, bool)
```

- Getter for the x/crypto Entity (internal components of an OpenPGP key) from Key struct
```go
(key *Key) GetEntity() *openpgp.Entity
```

- Helpers for binary message encryption and decryption
```go
EncryptBinaryMessageArmored(key string, data []byte) (string, error)
DecryptBinaryMessageArmored(privateKey string, passphrase []byte, ciphertext string) ([]byte, error)
```

- Method to derive a public key object from a private key
```go
(key *Key) ToPublic() (publicKey *Key, err error) 
```

- Helpers to handle encryption (both with armored and unarmored cipher) + encrypted detached signatures in one call.
```go
EncryptSignArmoredDetached(
	publicKey, privateKey string,
	passphrase, plainData []byte,
) (ciphertextArmored, encryptedSignatureArmored string, err error)

DecryptVerifyArmoredDetached(
	publicKey, privateKey string,
	passphrase []byte,
	ciphertextArmored string,
	encryptedSignatureArmored string,
) (plainData []byte, err error)
```
```go
EncryptSignBinaryDetached(
	publicKey, privateKey string,
	passphrase, plainData []byte,
) (encryptedData []byte, encryptedSignatureArmored string, err error)

DecryptVerifyBinaryDetached(
	publicKey, privateKey string,
	passphrase []byte,
	encryptedData []byte,
	encryptedSignatureArmored string,
) (plainData []byte, err error)
```
- Wrappers for `EncryptSignArmoredDetached` and `EncryptSignBinaryDetached` helpers, to be usable with gomobile (that doesn't support multiple retun values). These wrappers return custom structs instead.
```go
type EncryptSignArmoredDetachedMobileResult struct {
	CiphertextArmored, EncryptedSignatureArmored string
}

EncryptSignArmoredDetachedMobile(
	publicKey, privateKey string,
	passphrase, plainData []byte,
) (wrappedTuple *EncryptSignArmoredDetachedMobileResult, err error)
```
```go
type EncryptSignBinaryDetachedMobileResult struct {
	EncryptedData             []byte
	EncryptedSignatureArmored string
}

EncryptSignBinaryDetachedMobile(
	publicKey, privateKey string,
	passphrase, plainData []byte,
) (wrappedTuple *EncryptSignBinaryDetachedMobileResult, err error) 
```

- helpers to encrypt/decrypt session keys with armored keys:
```go
EncryptSessionKey(
	publicKey string,
	sessionKey *crypto.SessionKey,
) (encryptedSessionKey []byte, err error)

DecryptSessionKey(
	privateKey string,
	passphrase, encryptedSessionKey []byte,
) (sessionKey *crypto.SessionKey, err error)
```

- helpers to encrypt/decrypt binary files with armored keys:
```go
EncryptAttachmentWithKey(
	publicKey string,
	filename string,
	plainData []byte,
) (message *crypto.PGPSplitMessage, err error)

DecryptAttachmentWithKey(
	privateKey string,
	passphrase, keyPacket, dataPacket []byte,
) (attachment []byte, err error)
```

- `NewPlainMessageFromFile` Function to create new `PlainMessage`s with a filename:
```go
NewPlainMessageFromFile(data []byte, filename string, modTime int) *PlainMessage
```

- `GetFilename` to get the filename from a message:
```go 
(msg *PlainMessage) GetFilename() string
```

- `GetModTime` to get the modification time of a file
```go 
(msg *PlainMessage) GetModTime() uint32
```

- `EncryptWithCompression` to encrypt specifying a compression for asymmetric and session keys
```go
(keyRing *KeyRing) EncryptWithCompression(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error)

(sk *SessionKey) EncryptWithCompression(message *PlainMessage) ([]byte, error)
```

### Changed
- Improved key and message armoring testing
- `EncryptSessionKey` now creates encrypted key packets for each valid encryption key in the provided keyring. 
    Returns a byte slice with all the concatenated key packets.
- Use aes256 cipher for password-encrypted messages.
- The helpers `EncryptSignMessageArmored`, `DecryptVerifyMessageArmored`, `DecryptVerifyAttachment`, and`DecryptBinaryMessageArmored`
    now accept private keys as public keys and perform automatic casting if the keys are locked.
- The `PlainMessage` struct now contains the fields `Filename` (string) and `Time` (uint32)
- All the Decrypt* functions return the filename, type, and time specified in the encrypted message
- Improved error wrapping and management
- CI has been moved from travis to Actions, with automated artifacts build

### Fixed
- Public key armoring headers
- `EncryptSessionKey` throws an error when invalid encryption keys are provided
- Session keys' size is now checked against the expected value to prevent panics
- Hex Key IDs returned from `(key *Key) GetHexKeyID() string` are now correctly padded
- Avoid panics in `(msg *PGPMessage) GetEncryptionKeyIDs() ([]uint64, bool)` by breaking the packet.next cycle on specific packet types
- Prevent the server time from going backwards in `UpdateTime`
- Avoid panicking when messages with mixed symmetric/asymmetric key packets are decrypted with a password

## [2.0.1] - 2020-05-01
### Security
- Updated underlying crypto library
- Improved memory zeroing in helpers

### Fixed
- Fixed garbage collection issues when compiled on gomobile, by copying byte slices
- Password encrypted binary files now have the correct flags
- Fixed missing space in `Hash` header of cleartext messages
- Fixed tests `TestMultipleKeyMessageEncryption` and `TestSymmetricKeyPacket`

## Changed
- Providing empty passphrase does no longer throw an error when unlocking an unencrypted private key
- Improved code linter

### Added
- SHA256 fingerprint support
```go
(key *Key) GetSHA256Fingerprints() (fingerprints []string)

// Helper
GetSHA256Fingerprints(publicKey string) ([]string, error)

// Helper, mobile only, returns fingerprints encoded as JSON
GetJsonSHA256Fingerprints(publicKey string) ([]byte, error)
```

## [2.0.0] - 2020-01-06
Since the open-sourcing of the library in May the API has been updated, listening to internal and
external feedback, in order to have a flexible library, that can be used in a simple settings,
with batteries included, or by more advanced users that might want to interact directly with
the inner structure of the PGP messages and keys. 

It allows direct interaction with keys and keyrings, passphrases, as well as session keys.
It is designed with gomobile users in mind, so that they can use the full power of the library,
without having to rely on a further wrapper.

This version comes with some design improvements, in particular the introduction of keys
### Security
- Dropped the use of strings for secrets
- New key checking functions
- Clear memory after use, in an attempt to reduce leftover secrets in RAM.
- Improved testing, in this and the underlying crypto library

### Fixed
- `KeyRing`s can now only be unencrypted, removing the problem of mixed encrypted/decrypted keyring, that caused keys not to be recognised.
- Explicit key decryption and encryption.
- Underlying crypto library update.
- Underlying MIME library update.
- Fixed ECC critical bugs.
- Removed gopenpgp/pmcrypto object as it could create multiple globals. Methods are now static on the crypto object.

### Removed
- `Signature` struct
- `Signature#KeyRing` function
- `Signature#IsBy` function
- `pmKeyObject` struct
- `encodedLength` function, internal and and unused
- `EncryptCore` is now internal.
- `RandomTokenWith`, `RandomToken` now takes a size
- In the `KeyRing` struct:
    - `KeyRing#GetEntities`, entities are handled by the lib
    - `KeyRing#GetSigningEntity`, has been made internal
    - `KeyRing#Unlock`, the unlocking functionalities are on now on the key object
    - `BuildKeyRingNoError`, `BuildKeyRingArmored`, `BuildKeyRing` use `NewKey` or `NewKeyFromArmored` and handle errors
then join them into KeyRings. 
    - `ReadKeyRing`, `ReadArmoredKeyRing`, use `NewKeyFromArmoredReader` or `NewKeyFromReader`.
    - `UnmarshalJSON`, the interface to unmarshal JSON is not relevant to this library.


### Added
- `Key` struct, to store, import (unserialize) and export (serialize) keys.
```go
// Key contains a single private or public key
type Key struct {
	// PGP entities in this keyring.
	entity *openpgp.Entity
}

// With the functions
NewKeyFromArmoredReader(r io.Reader) (key *Key, err error)
NewKeyFromReader(r io.Reader) (key *Key, err error)
NewKey(binKeys []byte) (key *Key, err error)
NewKeyFromArmored(armored string) (key *Key, err error)
GenerateKey(name, email string, keyType string, bits int) (*Key, error)
GenerateRSAKeyWithPrimes(name, email string, bits int, primeone, primetwo, primethree, primefour []byte) (*Key, error)
(key *Key) Clone() (*Key, error)
(key *Key) Lock(passphrase []byte) (*Key, error)
(key *Key) Unlock(passphrase []byte) (*Key, error)
(key *Key) Serialize() ([]byte, error)
(key *Key) Armor() (string, error)
(key *Key) GetArmoredPublicKey() (s string, err error)
(key *Key) GetPublicKey() (b []byte, err error)
(key *Key) IsExpired() bool
(key *Key) IsPrivate() bool
(key *Key) IsLocked() (bool, error)
(key *Key) IsUnlocked() (bool, error)
(key *Key) Check() (bool, error)
(key *Key) PrintFingerprints()
(key *Key) GetHexKeyID() string
(key *Key) GetKeyID() uint64
(key *Key) GetFingerprint() string
(key *Key) ClearPrivateParams() (ok bool)
```

- In the `KeyRing` object:
```go
NewKeyRing(key *Key) (*KeyRing, error)
(keyRing *KeyRing) AddKey(key *Key) error
(keyRing *KeyRing) GetKeys() []*Key
(keyRing *KeyRing) GetKey(n int) (*Key, error)
(keyRing *KeyRing) CountEntities() int
(keyRing *KeyRing) CountDecryptionEntities() int
(keyRing *KeyRing) GetIdentities() []*Identity
(keyRing *KeyRing) FirstKey() (*KeyRing, error)
(keyRing *KeyRing) Clone() (*KeyRing, error)
(keyRing *KeyRing) ClearPrivateParams()
```

- `PlainMessage` struct, to store un-encrypted messages
```go
// PlainMessage stores a plain text / unencrypted message.
type PlainMessage struct {
	// The content of the message
	Data []byte
	// if the content is text or binary
	TextType bool
}

// With the functions
NewPlainMessage(data []byte) *PlainMessage
NewPlainMessageFromString(text string) *PlainMessage
(msg *PlainMessage) GetBinary()
(msg *PlainMessage) GetString()
(msg *PlainMessage) GetBase64()
(msg *PlainMessage) NewReader()
(msg *PlainMessage) IsText()
(msg *PlainMessage) IsBinary()
```

- `PGPMessage` struct, to store encrypted PGP messages
```go
// PGPMessage stores a PGP-encrypted message.
type PGPMessage struct {
	// The content of the message
	Data []byte
}

// With the functions
NewPGPMessage(data []byte) *PGPMessage
NewPGPMessageFromArmored(armored string) (*PGPMessage, error)
(msg *PGPMessage) GetBinary() []byte 
(msg *PGPMessage) NewReader() io.Reader
(msg *PGPMessage) GetArmored() (string, error)
(msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int) (outSplit *PGPSplitMessage, err error)
```

- `PGPSignature` struct, to store detached PGP signatures
```go
// PGPSignature stores a PGP-encoded detached signature.
type PGPSignature struct {
	// The content of the message
	Data []byte
}

// With the functions
NewPGPSignature(data []byte) *PGPSignature
NewPGPSignatureFromArmored(armored string) (*PGPSignature, error) 
(msg *PGPSignature) GetBinary() []byte
(msg *PGPSignature) GetArmored() (string, error)
```

- `SignatureVerificationError` struct, to separate signature verification errors from decryption errors
```go
// SignatureVerificationError is returned from Decrypt and VerifyDetached functions when signature verification fails
type SignatureVerificationError struct {
	Status int
	Message string
}
```

### Changed
- `IsKeyExpiredBin` has been renamed to `IsKeyExpired`
- `IsKeyExpired` has been renamed to `IsArmoredKeyExpired`
- `CheckKey` has been renamed to `PrintFingerprints`
- `KeyRing#ArmoredPublicKeyString` has been renamed to `KeyRing#GetArmoredPublicKey`
- `KeyRing#KeyIds` has been renamed to `KeyRing#GetKeyIDs`
- `GetTimeUnix` was renamed to `GetUnixTime`

- `EncryptedSplit` has been changed to `PGPSplitMessage`
```go
models.EncryptedSplit struct {
	DataPacket []byte
	KeyPacket  []byte
	Algo       string
}
// Is now
crypto.PGPSplitMessage struct {
	DataPacket []byte
	KeyPacket  []byte
}

// With the functions
NewPGPSplitMessage(keyPacket []byte, dataPacket []byte) *PGPSplitMessage
NewPGPSplitMessageFromArmored(encrypted string) (*PGPSplitMessage, error)
(msg *PGPSplitMessage) GetBinaryDataPacket() []byte
(msg *PGPSplitMessage) GetBinaryKeyPacket() []byte
(msg *PGPSplitMessage) GetBinary() []byte
(msg *PGPSplitMessage) GetArmored() (string, error)
```

- `DecryptSignedVerify` has been changed to `ExplicitVerifyMessage`
```go
models.DecryptSignedVerify struct {
	//clear text
	Plaintext string
	//bitmask verify status : 0
	Verify int
	//error message if verify failed
	Message string
}
// Is now
// ExplicitVerifyMessage contains explicitely the signature verification error, for gomobile users
type ExplicitVerifyMessage struct {
	Message *crypto.PlainMessage
	SignatureVerificationError *crypto.SignatureVerificationError
}
// With the new helper
DecryptExplicitVerify (pgpMessage *crypto.PGPMessage, privateKeyRing, publicKeyRing *crypto.KeyRing, verifyTime int64) (*ExplicitVerifyMessage, error)
```

- `SignedString` has been changed to `ClearTextMessage`
```go
// SignedString wraps string with Signature
type SignedString struct {
	String string
	Signed *Signature
}
// Is now
// ClearTextMessage, split signed clear text message container
type ClearTextMessage struct {
	Data []byte
	Signature []byte
}

// With the functions
NewClearTextMessage(data []byte, signature []byte) *ClearTextMessage
NewClearTextMessageFromArmored(signedMessage string) (*ClearTextMessage, error)
(msg *ClearTextMessage) GetBinary() []byte
(msg *ClearTextMessage) GetString() string
(msg *ClearTextMessage) GetBinarySignature() []byte
(msg *ClearTextMessage) GetArmored() (string, error)
```
- `SymmetricKey` has been renamed to `SessionKey`
```go
// SessionKey stores a decrypted session key.
type SessionKey struct {
	// The decrypted binary session key.
	Key []byte
	// The symmetric encryption algorithm used with this key.
	Algo string
}

// With the functions
NewSessionKeyFromToken(token []byte, algo string) *SessionKey
GenerateSessionKey() (*SessionKey, error)
GenerateSessionKeyAlgo(algo string) (sk *SessionKey, err error)
(sk *SessionKey) GetCipherFunc() packet.CipherFunction 
(sk *SessionKey) GetBase64Key() string
(sk *SessionKey) Encrypt(message *PlainMessage) ([]byte, error)
(sk *SessionKey) Decrypt(dataPacket []byte) (*PlainMessage, error)
(sk *SessionKey) Clear() (ok bool)
```

- `ReadClearSignedMessage` moved to crypto package and renamed to `NewClearTextMessageFromArmored`. Changed to return `ClearTextMessage`.
```go
ReadClearSignedMessage(signedMessage string) (string, error)
// Is now
NewClearTextMessageFromArmored(signedMessage string) (*ClearTextMessage, error)

// In addition, were added:
NewClearTextMessage(data []byte, signature []byte) *ClearTextMessage
(msg *ClearTextMessage) GetBinary() []byte
(msg *ClearTextMessage) GetString() string
(msg *ClearTextMessage) GetBinarySignature() []byte
(msg *ClearTextMessage) GetArmored() (string, error)

// As helpers were added:
SignCleartextMessageArmored(privateKey string, passphrase []byte, text string) (string, error)
VerifyCleartextMessageArmored(publicKey, armored string, verifyTime int64) (string, error)
SignCleartextMessage(keyRing *crypto.KeyRing, text string) (string, error)
VerifyCleartextMessage(keyRing *crypto.KeyRing, armored string, verifyTime int64) (string, error)
```

- `EncryptAttachment`'s parameters are changed to messages.
```go
(pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey *KeyRing) (*models.EncryptedSplit, error)
// Is now
(keyRing *KeyRing) EncryptAttachment(message *PlainMessage, fileName string) (*PGPSplitMessage, error)

// As a helper was added:
EncryptSignAttachment(publicKey, privateKey string, passphrase []byte, fileName string, plainData []byte) (keyPacket, dataPacket, signature []byte, err error)
```

- `DecryptAttachment` has been moved to KeyRing struct (like `EncryptAttachment`)
```go
(pm *PmCrypto) DecryptAttachment(keyPacket []byte, dataPacket []byte, kr *KeyRing, passphrase string) ([]byte, error)
// Is now
(keyRing *KeyRing) DecryptAttachment(message *PGPSplitMessage) (*PlainMessage, error)

// As a helper was added:
DecryptVerifyAttachment(publicKey, privateKey string, passphrase, keyPacket, dataPacket []byte, armoredSignature string) (plainData []byte, err error)
```

- `EncryptAttachmentLowMemory` was renamed to `NewLowMemoryAttachmentProcessor`.
```go
(pm *PmCrypto) EncryptAttachmentLowMemory(estimatedSize int, fileName string, publicKey *KeyRing) (*AttachmentProcessor, error)
// Is now
(keyRing *KeyRing) NewLowMemoryAttachmentProcessor(estimatedSize int, fileName string) (*AttachmentProcessor, error)
```

- `SplitArmor` was renamed to `NewPGPSplitMessageFromArmored` and the model changed.
```go
SplitArmor(encrypted string) (*models.EncryptedSplit, error)
// Is now
NewPGPSplitMessageFromArmored(encrypted string) (*PGPSplitMessage, error)
```

- `DecryptAttKey` was renamed to `DecryptSessionKey` and the parameter keypacket changed to `[]byte` as it's binary, not armored.
```go
DecryptAttKey(kr *KeyRing, keyPacket string) (key *SymmetricKey, err error):
// Is now
(keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SessionKey, error)
```

- `SetKey` has been renamed to `EncryptSessionKey`, and the keypacket return value changed to `[]byte`.
```go
SetKey(kr *KeyRing, symKey *SymmetricKey) (packets string, err error):
// Is now
(keyRing *KeyRing) EncryptSessionKey(sessionSplit *SessionKey) ([]byte, error)
```

- `SeparateKeyAndData` has been split in two different function, as it did not only separate the data, but when provided a KeyRing decrypted the session key too.
```go
SeparateKeyAndData(kr *KeyRing, r io.Reader, estimatedLength int, garbageCollector int) (outSplit *models.EncryptedSplit, err error):

// Is now the conjunction of the following function:
// To separate key and data
(msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int) (outSplit *PGPSplitMessage, err error)
// To decrypt the SessionKey
(keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SessionKey, error)
```

- `EncryptSymmetric` has been changed, now the procedure is split in two parts: `Encrypt` and `SeparateKeyAndData`
```go
(kr *KeyRing) EncryptSymmetric(textToEncrypt string, canonicalizeText bool) (outSplit *models.EncryptedSplit, err error):
// Is now the conjunction of the following function:
// To encrypt
(keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error)
// To separate key and data
(msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int) (outSplit *PGPSplitMessage, err error)
```

- `GenerateKey`'s signature has been altered:
  - It now returns a `Key` struct
  - `userName` and `domain` are now joined in `email`, the `name` parameter was added (To emulate the old behaviour `name = email = userName + "@" + domain`).
```go
(pm *PmCrypto) GenerateKey(userName, domain, passphrase, keyType string, bits int) (string, error) :
// Is now
GenerateKey(name, email string, keyType string, bits int) (*Key, error)

// As a helper was added:
GenerateKey(name, email string, passphrase []byte, keyType string, bits int) (string, error) 
```

- `GenerateRSAKeyWithPrimes`'s signature has been altered:
  - It now returns a `Key` struct
  - `userName` and `domain` are now joined in `email`, the `name` parameter was added (To emulate the old behaviour `name = email = userName + "@" + domain`).
```go
(pm *PmCrypto) GenerateRSAKeyWithPrimes(userName, domain, passphrase, keyType string, bits int, prime1, prime2, prime3, prime4 []byte) (string, error):
GenerateRSAKeyWithPrimes(name, email string, bits int, primeone, primetwo, primethree, primefour []byte,) (*Key, error)
```

- `Encrypt`, `EncryptArmored`, `EncryptString`, `EncryptMessage` functions have been changed to return and accept messages.
```go
(kr *KeyRing) Encrypt(w io.Writer, sign *KeyRing, filename string, canonicalizeText bool) (io.WriteCloser, error)
// Is now
(keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error)

// As a helpers were added:
EncryptMessageArmored(publicKey, plaintext string) (ciphertext string, err error)
EncryptSignMessageArmored(publicKey, privateKey string, passphrase []byte, plaintext string) (ciphertext string, err error) {
```

- `Decrypt`, `DecryptArmored`, `DecryptString`, `DecryptMessage`, `DecryptMessageVerify`, and `DecryptMessageStringKey` functions have been changed to return and accept messages (Same as Encrypt*).
If signature verification fails they will return a SignatureVerificationError.
```go
(kr *KeyRing) DecryptString(encrypted string) (SignedString, error)
// Is now
(keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*PlainMessage, error)

// As a helpers were added:
DecryptMessageArmored(privateKey string, passphrase []byte, ciphertext string) (plaintext string, err error)
DecryptVerifyMessageArmored(publicKey, privateKey string, passphrase []byte, ciphertext string) (plaintext string, err error)
DecryptExplicitVerify(pgpMessage *crypto.PGPMessage, privateKeyRing, publicKeyRing *crypto.KeyRing, verifyTime int64) (*ExplicitVerifyMessage, error) {
```
- `DecryptStringIfNeeded` has been replaced with `IsPGPMessage` + `Decrypt*`.
```go
(kr *KeyRing) DecryptStringIfNeeded(data string) (decrypted string, err error)
// Is now the conjunction of the following function:
// To check if the data is a PGP message
IsPGPMessage(data string) bool
// To decrypt
(keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*PlainMessage, error)
```

- `SignString` and `DetachedSign` have been replaced by signing methods.
```go
(kr *KeyRing) SignString(message string, canonicalizeText bool) (signed string, err error)
(kr *KeyRing) DetachedSign(w io.Writer, toSign io.Reader, canonicalizeText bool, armored bool)
// Are now
(keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error)
```

- `VerifyString` has been altered in the same way as as signing. 
Returns SignatureVerificationError if the verification fails.
```go
(kr *KeyRing) VerifyString(message, signature string, sign *KeyRing) (err error)
// Is now
(keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) error
```

- `EncryptMessageWithPassword` uses AES-256 instead of AES-128, and has a new signature.
```go
(pm *PmCrypto) EncryptMessageWithPassword(plaintext string, password string) (string, error)
// Is now
EncryptMessageWithPassword(message *PlainMessage, password []byte) (*PGPMessage, error)

// As a helper was added:
EncryptMessageWithPassword(password []byte, plaintext string) (ciphertext string, err error)
```

- `DecryptMessageWithPassword` accepts all symmetric algorithms known to the lib, and has a new signature
```go
(pm *PmCrypto) DecryptMessageWithPassword(encrypted string, password string) (string, error)
// Is now
DecryptMessageWithPassword(message *PGPMessage, password []byte) (*PlainMessage, error)

// As a helper was added:
DecryptMessageWithPassword(password []byte, ciphertext string) (plaintext string, err error)
```

- `DecryptMIMEMessage` was moved to `KeyRing`, and the parameters transformed to messages
```go
(pm *PmCrypto) DecryptMIMEMessage(encryptedText string, verifierKey *KeyRing, privateKeyRing *KeyRing, passphrase string, callbacks MIMECallbacks, verifyTime int64):
// Is now
(keyRing *KeyRing) DecryptMIMEMessage(message *PGPMessage, verifyKey *KeyRing, callbacks MIMECallbacks, verifyTime int64)
```

- `RandomToken` now takes a size
```go
(pm *PmCrypto) RandomToken() ([]byte, error)
// Is now
RandomToken(size int) ([]byte, error)
```

- `GetSessionFromKeyPacket` was changed to `DecryptSessionKey`.
```go
(pm *PmCrypto) GetSessionFromKeyPacket(keyPackage []byte, privateKey *KeyRing, passphrase string) (*SymmetricKey, error)
// Is now
(keyRing *KeyRing) DecryptSessionKey(keyPacket []byte) (*SessionKey, error)
```

- `KeyPacketWithPublicKey` and `KeyPacketWithPublicKeyBin` have been merged to `EncryptSessionKey`.
```go
(pm *PmCrypto) KeyPacketWithPublicKey(sessionSplit *SymmetricKey, publicKey string) ([]byte, error)
(pm *PmCrypto) KeyPacketWithPublicKeyBin(sessionSplit *SymmetricKey, publicKey []byte) ([]byte, error)
(keyRing *KeyRing) EncryptSessionKey(sk *SessionKey) ([]byte, error)
```

- `GetSessionFromSymmetricPacket` was renamed to `DecryptSessionKeyWithPassword`.
```go
(pm *PmCrypto) GetSessionFromSymmetricPacket(keyPackage []byte, password string) (*SymmetricKey, error)
// Is now
DecryptSessionKeyWithPassword(keyPacket, password []byte) (*SessionKey, error)
```

- `SymmetricKeyPacketWithPassword` has been renamed to `EncryptSessionKeyWithPassword`
```go
(pm *PmCrypto) SymmetricKeyPacketWithPassword(sessionSplit *SymmetricKey, password string) ([]byte, error):
EncryptSessionKeyWithPassword(sk *SessionKey, password []byte]) ([]byte, error)
```

- `SignTextDetached` and `SignBinDetached` have been changed to `SignDetached`
```go
(pm *PmCrypto) SignTextDetached(plaintext string, privateKey *KeyRing, passphrase string, trim bool) (string, error)
(pm *PmCrypto) SignBinDetached(plainData []byte, privateKey *KeyRing, passphrase string) (string, error)
// Are now
(keyRing *KeyRing) SignDetached(message *PlainMessage) (*PGPSignature, error)

// As helpers were added:
SignCleartextMessage(keyRing *crypto.KeyRing, text string) (string, error) 
SignCleartextMessageArmored(privateKey string, passphrase []byte, text string) (string, error)
```

- `VerifyTextSignDetachedBinKey` and `VerifyBinSignDetachedBinKey` have been changed to `Verify`.
```go
(pm *PmCrypto) VerifyTextSignDetachedBinKey(signature string, plaintext string, publicKey *KeyRing, verifyTime int64) (bool, error):
(pm *PmCrypto) VerifyBinSignDetachedBinKey(signature string, plainData []byte, publicKey *KeyRing, verifyTime int64) (bool, error)
// Are now
(keyRing *KeyRing) VerifyDetached(message *PlainMessage, signature *PGPSignature, verifyTime int64) error

// As helpers were added:
VerifyCleartextMessage(keyRing *crypto.KeyRing, armored string, verifyTime int64) (string, error)
VerifyCleartextMessageArmored(publicKey, armored string, verifyTime int64) (string, error)
```

## [1.0.0] - 2019-05-15
Initial release, opensourcing of the internal library `PMCrypto`, and subsequent renaming to `gopenpgp`
