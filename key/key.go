// Provides key manipulation helper methods
package key

import (
	"bytes"
	"fmt"
	"github.com/ProtonMail/go-pm-crypto/armor"
	"github.com/ProtonMail/go-pm-crypto/constants"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"strings"
)

// CheckPassphrase checks if private key passphrase ok
func CheckPassphrase(privateKey string, passphrase string) bool {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := openpgp.ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		fmt.Println(err)
		return false
	}

	var keys []*packet.PrivateKey

	for _, e := range entries {
		keys = append(keys, e.PrivateKey)
	}
	var decryptError error
	var n int
	for _, key := range keys {
		if !key.Encrypted {
			continue // Key already decrypted
		}
		if decryptError = key.Decrypt([]byte(passphrase)); decryptError == nil {
			n++
		}
	}
	if n == 0 {
		return false
	}
	return true
}

// PublicKey gets a public key from a private key
func PublicKey(privateKey string) (string, error) {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := openpgp.ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return "", err
	}

	var outBuf bytes.Buffer
	for _, e := range entries {
		e.Serialize(&outBuf)
	}

	outString, err := armor.ArmorWithType(outBuf.Bytes(), constants.PublicKeyHeader)
	if err != nil {
		return "", nil
	}

	return outString, nil
}

// PublicKeyBinOut gets a public key from a private key
func PublicKeyBinOut(privateKey string) ([]byte, error) {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := openpgp.ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return nil, err
	}

	var outBuf bytes.Buffer
	for _, e := range entries {
		e.Serialize(&outBuf)
	}

	return outBuf.Bytes(), nil
}
