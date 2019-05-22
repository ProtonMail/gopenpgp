package helper

import (
	"errors"
	"strings"

	"github.com/ProtonMail/gopenpgp/armor"
	"github.com/ProtonMail/gopenpgp/crypto"
	"github.com/ProtonMail/gopenpgp/internal"
)

// SignCleartextMessageArmored signs text given a private key and its passphrase, canonicalizes and trims the newlines,
// and returns the PGP-compliant special armoring
func SignCleartextMessageArmored(privateKey, passphrase, text string) (string, error) {
	signingKeyRing, err := pgp.BuildKeyRingArmored(privateKey)
	if err != nil {
		return "", err
	}

	err = signingKeyRing.UnlockWithPassphrase(passphrase)
	if err != nil {
		return "", err
	}

	return SignCleartextMessage(signingKeyRing, text)
}

// VerifyCleartextMessageArmored verifies PGP-compliant armored signed plain text given the public key
// and returns the text or err if the verification fails
func VerifyCleartextMessageArmored(publicKey, armored string, verifyTime int64) (string, error) {
	verifyKeyRing, err := pgp.BuildKeyRingArmored(publicKey)
	if err != nil {
		return "", err
	}

	return VerifyCleartextMessage(verifyKeyRing, armored, verifyTime)
}

// SignCleartextMessage signs text given a private keyring, canonicalizes and trims the newlines,
// and returns the PGP-compliant special armoring
func SignCleartextMessage(keyRing *crypto.KeyRing, text string) (string, error) {
	text = canonicalizeAndTrim(text)
	message := crypto.NewPlainMessageFromString(text)

	message, signature, err := keyRing.SignDetached(message)
	if err != nil {
		return "", err
	}

	return armor.ArmorClearSignedMessage(message.GetBinary(), signature.GetBinary())
}

// VerifyCleartextMessage verifies PGP-compliant armored signed plain text given the public keyring
// and returns the text or err if the verification fails
func VerifyCleartextMessage(keyRing *crypto.KeyRing, armored string, verifyTime int64) (string, error) {
	text, signatureData, err := armor.ReadClearSignedMessage(armored)
	if err != nil {
		return "", err
	}

	message := crypto.NewPlainMessageFromString(text)
	signature := crypto.NewPGPSignature(signatureData)
	message, err = keyRing.VerifyDetached(message, signature, verifyTime)
	if err != nil {
		return "", err
	}

	if !message.IsVerified() {
		return "", errors.New("gopenpgp: unable to verify attachment")
	}

	return message.GetString(), nil
}

// ----- INTERNAL FUNCTIONS -----

// canonicalizeAndTrim alters a string canonicalizing and trimming the newlines
func canonicalizeAndTrim(text string) string {
	text = internal.TrimNewlines(text)
	text = strings.Replace(strings.Replace(text, "\r\n", "\n", -1), "\n", "\r\n", -1)
	return text
}
