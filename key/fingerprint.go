package key

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/ProtonMail/go-pm-crypto/armor"
	"golang.org/x/crypto/openpgp"
)

// GetFingerprint gets an armored public key fingerprint
func GetFingerprint(publicKey string) (string, error) {
	rawPubKey, err := armor.Unarmor(publicKey)
	if err != nil {
		return "", err
	}
	return GetFingerprintBinKey(rawPubKey)
}

// GetFingerprintBinKey gets an unarmored public key fingerprint
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
	return "", errors.New("can't find public key")
}
