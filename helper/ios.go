package helper

import (
	"github.com/ProtonMail/gopenpgp/crypto"
)

type ExplicitVerifyMessage struct {
	Message *crypto.PlainMessage
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

	message, err := privateKeyRing.Decrypt(pgpMessage, publicKeyRing, verifyTime);

	if err != nil {
		castedErr, isType := err.(crypto.SignatureVerificationError)
		if !isType {
			return nil, err
		}

		explicitVerify = &ExplicitVerifyMessage{
			Message: message,
			SignatureVerificationError: &castedErr,
		}
	} else {
		explicitVerify = &ExplicitVerifyMessage{
			Message: message,
			SignatureVerificationError: nil,
		}
	}

	return explicitVerify, nil
}
