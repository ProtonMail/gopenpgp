// +build !ios
// +build !android

package helper

import "github.com/ProtonMail/gopenpgp/v2/crypto"

// EncryptSignAttachment encrypts an attachment using a detached signature, given a publicKey, a privateKey
// and its passphrase, the filename, and the unencrypted file data.
// Returns keypacket, dataPacket and unarmored (!) signature separate.
func EncryptSignAttachment(
	publicKey, privateKey string, passphrase []byte, fileName string, plainData []byte,
) (keyPacket, dataPacket, signature []byte, err error) {
	var publicKeyObj, privateKeyObj, unlockedKeyObj *crypto.Key
	var publicKeyRing, privateKeyRing *crypto.KeyRing
	var packets *crypto.PGPSplitMessage
	var signatureObj *crypto.PGPSignature

	var binMessage = crypto.NewPlainMessage(plainData)

	if publicKeyObj, err = crypto.NewKeyFromArmored(publicKey); err != nil {
		return nil, nil, nil, err
	}

	if publicKeyRing, err = crypto.NewKeyRing(publicKeyObj); err != nil {
		return nil, nil, nil, err
	}

	if privateKeyObj, err = crypto.NewKeyFromArmored(privateKey); err != nil {
		return nil, nil, nil, err
	}

	if packets, err = publicKeyRing.EncryptAttachment(binMessage, fileName); err != nil {
		return nil, nil, nil, err
	}

	if unlockedKeyObj, err = privateKeyObj.Unlock(passphrase); err != nil {
		return nil, nil, nil, err
	}

	if privateKeyRing, err = crypto.NewKeyRing(unlockedKeyObj); err != nil {
		unlockedKeyObj.ClearPrivateParams()
		return nil, nil, nil, err
	}

	if signatureObj, err = privateKeyRing.SignDetached(binMessage); err != nil {
		unlockedKeyObj.ClearPrivateParams()
		return nil, nil, nil, err
	}
	unlockedKeyObj.ClearPrivateParams()

	return packets.GetBinaryKeyPacket(), packets.GetBinaryDataPacket(), signatureObj.GetBinary(), nil
}
