// Package helper contains several functions with a simple interface to extend usability and compatibility with gomobile
package helper

import (
	"errors"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// EncryptMessageWithPassword encrypts a string with a passphrase using AES256.
func EncryptMessageWithPassword(password []byte, plaintext string) (ciphertext string, err error) {
	var pgpMessage *crypto.PGPMessage

	var message = crypto.NewPlainMessageFromString(plaintext)

	if pgpMessage, err = crypto.EncryptMessageWithPassword(message, password); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

// DecryptMessageWithPassword decrypts an armored message with a random token.
// The algorithm is derived from the armoring.
func DecryptMessageWithPassword(password []byte, ciphertext string) (plaintext string, err error) {
	var message *crypto.PlainMessage
	var pgpMessage *crypto.PGPMessage

	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if message, err = crypto.DecryptMessageWithPassword(pgpMessage, password); err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// EncryptMessageArmored generates an armored PGP message given a plaintext and
// an armored public key.
func EncryptMessageArmored(key, plaintext string) (string, error) {
	return encryptMessageArmored(key, crypto.NewPlainMessageFromString(plaintext))
}

// EncryptSignMessageArmored generates an armored signed PGP message given a
// plaintext and an armored public key a private key and its passphrase.
func EncryptSignMessageArmored(
	publicKey, privateKey string, passphrase []byte, plaintext string,
) (ciphertext string, err error) {
	var publicKeyObj, privateKeyObj, unlockedKeyObj *crypto.Key
	var publicKeyRing, privateKeyRing *crypto.KeyRing
	var pgpMessage *crypto.PGPMessage

	var message = crypto.NewPlainMessageFromString(plaintext)

	if publicKeyObj, err = crypto.NewKeyFromArmored(publicKey); err != nil {
		return "", err
	}
	if publicKeyObj.IsPrivate() {
		publicKeyObj, err = publicKeyObj.ToPublic()
		if err != nil {
			return "", err
		}
	}

	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return "", err
	}

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return "", err
	}

	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return "", err
	}
	defer unlockedKeyObj.ClearPrivateParams()

	if privateKeyRing, err = crypto.NewKeyRing(unlockedKeyObj); err != nil {
		return "", err
	}

	if pgpMessage, err = publicKeyRing.Encrypt(message, privateKeyRing); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

// DecryptMessageArmored decrypts an armored PGP message given a private key
// and its passphrase.
func DecryptMessageArmored(
	privateKey string, passphrase []byte, ciphertext string,
) (string, error) {
	message, err := decryptMessageArmored(privateKey, passphrase, ciphertext)

	if err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// DecryptVerifyMessageArmored decrypts an armored PGP message given a private
// key and its passphrase and verifies the embedded signature. Returns the
// plain data or an error on signature verification failure.
func DecryptVerifyMessageArmored(
	publicKey, privateKey string, passphrase []byte, ciphertext string,
) (plaintext string, err error) {
	var publicKeyObj, privateKeyObj, unlockedKeyObj *crypto.Key
	var publicKeyRing, privateKeyRing *crypto.KeyRing
	var pgpMessage *crypto.PGPMessage
	var message *crypto.PlainMessage

	if publicKeyObj, err = crypto.NewKeyFromArmored(publicKey); err != nil {
		return "", err
	}
	if publicKeyObj.IsPrivate() {
		publicKeyObj, err = publicKeyObj.ToPublic()
		if err != nil {
			return "", err
		}
	}

	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return "", err
	}

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return "", err
	}

	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return "", err
	}
	defer unlockedKeyObj.ClearPrivateParams()

	if privateKeyRing, err = crypto.NewKeyRing(unlockedKeyObj); err != nil {
		return "", err
	}

	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if message, err = privateKeyRing.Decrypt(pgpMessage, publicKeyRing, crypto.GetUnixTime()); err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// DecryptVerifyAttachment decrypts and verifies an attachment split into the
// keyPacket, dataPacket and an armored (!) signature, given a publicKey, and a
// privateKey with its passphrase. Returns the plain data or an error on
// signature verification failure.
func DecryptVerifyAttachment(
	publicKey, privateKey string,
	passphrase, keyPacket, dataPacket []byte,
	armoredSignature string,
) (plainData []byte, err error) {
	// We decrypt the attachment
	message, err := decryptAttachment(privateKey, passphrase, keyPacket, dataPacket)
	if err != nil {
		return nil, err
	}

	// We verify the signature
	var check bool
	if check, err = verifyDetachedArmored(publicKey, message, armoredSignature); err != nil {
		return nil, err
	}
	if !check {
		return nil, errors.New("gopenpgp: unable to verify attachment")
	}

	return message.GetBinary(), nil
}

// EncryptBinaryMessageArmored generates an armored PGP message given a binary data and
// an armored public key.
func EncryptBinaryMessageArmored(key string, data []byte) (string, error) {
	return encryptMessageArmored(key, crypto.NewPlainMessage(data))
}

// DecryptBinaryMessageArmored decrypts an armored PGP message given a private key
// and its passphrase.
func DecryptBinaryMessageArmored(privateKey string, passphrase []byte, ciphertext string) ([]byte, error) {
	message, err := decryptMessageArmored(privateKey, passphrase, ciphertext)

	if err != nil {
		return nil, err
	}

	return message.GetBinary(), nil
}

// EncryptSignArmoredDetached takes a public key for encryption,
// a private key and its passphrase for signature, and the plaintext data
// Returns an armored ciphertext and a detached armored signature.
func EncryptSignArmoredDetached(
	publicKey, privateKey string,
	passphrase, plainData []byte,
) (ciphertext, signature string, err error) {
	var message *crypto.PlainMessage = crypto.NewPlainMessage(plainData)

	// We encrypt the message
	if ciphertext, err = encryptMessageArmored(publicKey, message); err != nil {
		return "", "", err
	}

	// We sign the message
	if signature, err = signDetachedArmored(privateKey, passphrase, message); err != nil {
		return "", "", err
	}

	return ciphertext, signature, nil
}

// DecryptVerifyArmoredDetached decrypts an armored pgp message
// and verify a detached armored signature
// given a publicKey, and a privateKey with its passphrase.
// Returns the plain data or an error on
// signature verification failure.
func DecryptVerifyArmoredDetached(
	publicKey, privateKey string,
	passphrase []byte,
	ciphertext string,
	armoredSignature string,
) (plainData []byte, err error) {
	var message *crypto.PlainMessage

	// We decrypt the message
	if message, err = decryptMessageArmored(privateKey, passphrase, ciphertext); err != nil {
		return nil, err
	}

	// We verify the signature
	var check bool
	if check, err = verifyDetachedArmored(publicKey, message, armoredSignature); err != nil {
		return nil, err
	}
	if !check {
		return nil, errors.New("gopenpgp: unable to verify message")
	}

	return message.GetBinary(), nil
}

func EncryptAttachmentWithKey(
	publicKey string,
	filename string,
	plainData []byte,
) (message *crypto.PGPSplitMessage, err error) {
	publicKeyObj, err := crypto.NewKeyFromArmored(publicKey)

	if publicKeyObj.IsPrivate() {
		publicKeyObj, err = publicKeyObj.ToPublic()
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	publicKeyRing, err := crypto.NewKeyRing(publicKeyObj)

	if err != nil {
		return nil, err
	}
	return EncryptAttachment(plainData, filename, publicKeyRing)
}

func DecryptAttachmentWithKey(
	privateKey string,
	passphrase, keyPacket, dataPacket []byte,
) (attachment []byte, err error) {
	message, err := decryptAttachment(privateKey, passphrase, keyPacket, dataPacket)
	if err != nil {
		return nil, err
	}
	return message.GetBinary(), nil
}

func encryptMessageArmored(key string, message *crypto.PlainMessage) (string, error) {
	publicKey, err := crypto.NewKeyFromArmored(key)
	if publicKey.IsPrivate() {
		publicKey, err = publicKey.ToPublic()
		if err != nil {
			return "", err
		}
	}

	if err != nil {
		return "", err
	}

	publicKeyRing, err := crypto.NewKeyRing(publicKey)

	if err != nil {
		return "", err
	}

	pgpMessage, err := publicKeyRing.Encrypt(message, nil)

	if err != nil {
		return "", err
	}

	ciphertext, err := pgpMessage.GetArmored()

	if err != nil {
		return "", err
	}

	return ciphertext, nil
}

func decryptMessageArmored(privateKey string, passphrase []byte, ciphertext string) (*crypto.PlainMessage, error) {
	privateKeyObj, err := crypto.NewKeyFromArmored(privateKey)

	if err != nil {
		return nil, err
	}

	privateKeyUnlocked, err := privateKeyObj.Unlock(passphrase)

	if err != nil {
		return nil, err
	}

	defer privateKeyUnlocked.ClearPrivateParams()

	privateKeyRing, err := crypto.NewKeyRing(privateKeyUnlocked)

	if err != nil {
		return nil, err
	}

	pgpMessage, err := crypto.NewPGPMessageFromArmored(ciphertext)

	if err != nil {
		return nil, err
	}

	message, err := privateKeyRing.Decrypt(pgpMessage, nil, 0)

	if err != nil {
		return nil, err
	}

	return message, nil
}

func signDetachedArmored(privateKey string, passphrase []byte, message *crypto.PlainMessage) (signature string, err error) {
	privateKeyObj, err := crypto.NewKeyFromArmored(privateKey)

	if err != nil {
		return "", err
	}

	privateKeyUnlocked, err := privateKeyObj.Unlock(passphrase)

	if err != nil {
		return "", err
	}

	defer privateKeyUnlocked.ClearPrivateParams()

	privateKeyRing, err := crypto.NewKeyRing(privateKeyUnlocked)

	if err != nil {
		return "", err
	}

	detachedSignature, err := privateKeyRing.SignDetached(message)

	if err != nil {
		return "", err
	}

	armoredSignature, err := detachedSignature.GetArmored()

	if err != nil {
		return "", err
	}

	return armoredSignature, nil
}

func verifyDetachedArmored(publicKey string, message *crypto.PlainMessage, armoredSignature string) (check bool, err error) {
	var publicKeyObj *crypto.Key
	var publicKeyRing *crypto.KeyRing
	var detachedSignature *crypto.PGPSignature
	// We prepare the public key for signature verification
	if publicKeyObj, err = crypto.NewKeyFromArmored(publicKey); err != nil {
		return false, err
	}
	if publicKeyObj.IsPrivate() {
		publicKeyObj, err = publicKeyObj.ToPublic()
		if err != nil {
			return false, err
		}
	}
	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return false, err
	}

	// We verify the signature
	if detachedSignature, err = crypto.NewPGPSignatureFromArmored(armoredSignature); err != nil {
		return false, err
	}
	if publicKeyRing.VerifyDetached(message, detachedSignature, crypto.GetUnixTime()) != nil {
		return false, nil
	}
	return true, nil
}

func decryptAttachment(
	privateKey string,
	passphrase, keyPacket, dataPacket []byte,
) (message *crypto.PlainMessage, err error) {
	var privateKeyObj, unlockedKeyObj *crypto.Key
	var privateKeyRing *crypto.KeyRing

	packets := crypto.NewPGPSplitMessage(keyPacket, dataPacket)

	// prepare the private key for decryption
	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return nil, err
	}
	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return nil, err
	}
	defer unlockedKeyObj.ClearPrivateParams()

	if privateKeyRing, err = crypto.NewKeyRing(unlockedKeyObj); err != nil {
		return nil, err
	}

	if message, err = privateKeyRing.DecryptAttachment(packets); err != nil {
		return nil, err
	}

	return message, nil
}
