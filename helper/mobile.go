package helper

import (
	"encoding/json"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type ExplicitVerifyMessage struct {
	Message                    *crypto.PlainMessage
	SignatureVerificationError *crypto.SignatureVerificationError
}

// DecryptVerifyMessageArmored decrypts an armored PGP message given a private key and its passphrase
// and verifies the embedded signature.
// Returns the plain data or an error on signature verification failure.
func DecryptExplicitVerify(
	pgpMessage *crypto.PGPMessage,
	privateKeyRing, publicKeyRing *crypto.KeyRing,
	verifyTime int64,
) (*ExplicitVerifyMessage, error) {
	var explicitVerify *ExplicitVerifyMessage

	message, err := privateKeyRing.Decrypt(pgpMessage, publicKeyRing, verifyTime)

	if err != nil {
		castedErr, isType := err.(crypto.SignatureVerificationError)
		if !isType {
			return nil, err
		}

		explicitVerify = &ExplicitVerifyMessage{
			Message:                    message,
			SignatureVerificationError: &castedErr,
		}
	} else {
		explicitVerify = &ExplicitVerifyMessage{
			Message:                    message,
			SignatureVerificationError: nil,
		}
	}

	return explicitVerify, nil
}

// DecryptAttachment takes a keypacket and datpacket
// and returns a decrypted PlainMessage
// Specifically designed for attachments rather than text messages.
func DecryptAttachment(keyPacket []byte, dataPacket []byte, keyRing *crypto.KeyRing) (*crypto.PlainMessage, error) {
	splitMessage := crypto.NewPGPSplitMessage(keyPacket, dataPacket)

	decrypted, err := keyRing.DecryptAttachment(splitMessage)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// EncryptAttachment encrypts a file given a plainData and a fileName.
// Returns a PGPSplitMessage containing a session key packet and symmetrically encrypted data.
// Specifically designed for attachments rather than text messages.
func EncryptAttachment(plainData []byte, fileName string, keyRing *crypto.KeyRing) (*crypto.PGPSplitMessage, error) {
	plainMessage := crypto.NewPlainMessage(plainData)
	decrypted, err := keyRing.EncryptAttachment(plainMessage, fileName)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func GetJsonSHA256Fingerprints(publicKey string) ([]byte, error) {
	key, err := crypto.NewKeyFromArmored(publicKey)
	if err != nil {
		return nil, err
	}

	return json.Marshal(key.GetSHA256Fingerprints())
}
