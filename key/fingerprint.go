package key

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/ProtonMail/go-pm-crypto/armor"
	"golang.org/x/crypto/openpgp"
)

// Use: ios/android only
// GetFingerprint get a armored public key fingerprint
func GetFingerprint(publicKey string) (string, error) {
	rawPubKey, err := armor.Unarmor(publicKey)
	if err != nil {
		return "", err
	}
	return GetFingerprintBinKey(rawPubKey)
}

// Use: ios/android only
// GetFingerprintBinKey get a unarmored public key fingerprint
func GetFingerprintBinKey(publicKey []byte) (string, error) {
	pubKeyReader := bytes.NewReader(publicKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return "", err
	}
	for _, e := range pubKeyEntries {
		fp := e.PrimaryKey.Fingerprint
		return hex.EncodeToString(fp[:]), nil
	}
	return "", errors.New("Can't find public key")
}
