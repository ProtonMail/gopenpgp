// helper contains several functions with a simple interface to extend usability and compatibility with gomobile
package helper

import (
	"errors"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// EncryptMessageWithPassword encrypts a string with a passphrase using AES256
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

// EncryptMessageArmored generates an armored PGP message given a plaintext and an armored public key
func EncryptMessageArmored(key, plaintext string) (ciphertext string, err error) {
	var publicKey *crypto.Key
	var publicKeyRing *crypto.KeyRing
	var pgpMessage *crypto.PGPMessage

	var message = crypto.NewPlainMessageFromString(plaintext)

	if publicKey, err = crypto.NewKeyFromArmored(key); err != nil {
		return "", err
	}

	if publicKeyRing, err = crypto.NewKeyRing(publicKey); err != nil {
		return "", err
	}

	if pgpMessage, err = publicKeyRing.Encrypt(message, nil); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

// EncryptSignMessageArmored generates an armored signed PGP message given a plaintext and an armored public key
// a private key and its passphrase
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

	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return "", err
	}

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return "", err
	}

	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return "", err
	}

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

// DecryptMessageArmored decrypts an armored PGP message given a private key and its passphrase
func DecryptMessageArmored(
	privateKey string, passphrase []byte, ciphertext string,
) (plaintext string, err error) {
	var privateKeyObj, privateKeyUnlocked *crypto.Key
	var privateKeyRing *crypto.KeyRing
	var pgpMessage *crypto.PGPMessage
	var message *crypto.PlainMessage

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return "", err
	}

	if privateKeyUnlocked, err = privateKeyObj.Unlock(passphrase); err != nil {
		return "", err
	}

	if privateKeyRing, err = crypto.NewKeyRing(privateKeyUnlocked); err != nil {
		return "", err
	}

	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if message, err = privateKeyRing.Decrypt(pgpMessage, nil, 0); err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// DecryptVerifyMessageArmored decrypts an armored PGP message given a private key and its passphrase
// and verifies the embedded signature.
// Returns the plain data or an error on signature verification failure.
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

	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return "", err
	}

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return "", err
	}

	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return "", err
	}

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

// EncryptSignAttachment encrypts an attachment using a detached signature, given a publicKey, a privateKey
// and its passphrase, the filename, and the unencrypted file data.
// Returns keypacket, dataPacket and unarmored (!) signature separate.
// func EncryptSignAttachment(
// 	publicKey, privateKey string, passphrase []byte, fileName string, plainData []byte,
// ) (keyPacket, dataPacket, signature []byte, err error) {
// 	var publicKeyObj, privateKeyObj, unlockedKeyObj *crypto.Key
// 	var publicKeyRing, privateKeyRing *crypto.KeyRing
// 	var packets *crypto.PGPSplitMessage
// 	var signatureObj *crypto.PGPSignature

// 	var binMessage = crypto.NewPlainMessage(plainData)

// 	if publicKeyObj, err = crypto.NewKeyFromArmored(publicKey); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	if privateKeyRing, err = crypto.NewKeyRing(unlockedKeyObj); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	if packets, err = publicKeyRing.EncryptAttachment(binMessage, fileName); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	if signatureObj, err = privateKeyRing.SignDetached(binMessage); err != nil {
// 		return nil, nil, nil, err
// 	}

// 	return packets.GetBinaryKeyPacket(), packets.GetBinaryDataPacket(), signatureObj.GetBinary(), nil
// }

// DecryptVerifyAttachment decrypts and verifies an attachment split into the keyPacket, dataPacket
// and an armored (!) signature, given a publicKey, and a privateKey with its passphrase.
// Returns the plain data or an error on signature verification failure.
func DecryptVerifyAttachment(
	publicKey, privateKey string,
	passphrase, keyPacket, dataPacket []byte,
	armoredSignature string,
) (plainData []byte, err error) {
	var publicKeyObj, privateKeyObj, unlockedKeyObj *crypto.Key
	var publicKeyRing, privateKeyRing *crypto.KeyRing
	var detachedSignature *crypto.PGPSignature
	var message *crypto.PlainMessage

	var packets = crypto.NewPGPSplitMessage(keyPacket, dataPacket)

	if publicKeyObj, err = crypto.NewKeyFromArmored(publicKey); err != nil {
		return nil, err
	}

	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return nil, err
	}

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return nil, err
	}

	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return nil, err
	}

	if privateKeyRing, err = crypto.NewKeyRing(unlockedKeyObj); err != nil {
		return nil, err
	}

	if detachedSignature, err = crypto.NewPGPSignatureFromArmored(armoredSignature); err != nil {
		return nil, err
	}

	if message, err = privateKeyRing.DecryptAttachment(packets); err != nil {
		return nil, err
	}

	if publicKeyRing.VerifyDetached(message, detachedSignature, crypto.GetUnixTime()) != nil {
		return nil, errors.New("gopenpgp: unable to verify attachment")
	}

	return message.GetBinary(), nil
}
