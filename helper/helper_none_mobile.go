// +build !mobile

package helper

import "github.com/ProtonMail/gopenpgp/crypto"

// EncryptSignAttachment encrypts an attachment using a detached signature, given a publicKey, a privateKey
// and its passphrase, the filename, and the unencrypted file data.
// Returns keypacket, dataPacket and unarmored (!) signature separate.
func EncryptSignAttachment(
	publicKey, privateKey, passphrase, fileName string,
	plainData []byte,
) (keyPacket, dataPacket, signature []byte, err error) {
	var publicKeyRing, privateKeyRing *crypto.KeyRing
	var packets *crypto.PGPSplitMessage
	var signatureObj *crypto.PGPSignature

	var binMessage = crypto.NewPlainMessage(plainData)

	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
		return nil, nil, nil, err
	}

	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
		return nil, nil, nil, err
	}

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return nil, nil, nil, err
	}

	if packets, err = publicKeyRing.EncryptAttachment(binMessage, fileName); err != nil {
		return nil, nil, nil, err
	}

	if signatureObj, err = privateKeyRing.SignDetached(binMessage); err != nil {
		return nil, nil, nil, err
	}

	return packets.GetBinaryKeyPacket(), packets.GetBinaryDataPacket(), signatureObj.GetBinary(), nil
}
