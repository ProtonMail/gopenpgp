package helper

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// UpdatePrivateKeyPassphrase decrypts the given armored privateKey with oldPassphrase,
// re-encrypts it with newPassphrase, and returns the new armored key.
func UpdatePrivateKeyPassphrase(
	privateKey string,
	oldPassphrase, newPassphrase []byte,
) (string, error) {
	key, err := crypto.NewKeyFromArmored(privateKey)
	if err != nil {
		return "", err
	}

	unlocked, err := key.Unlock(oldPassphrase)
	if err != nil {
		return "", err
	}

	locked, err := unlocked.Lock(newPassphrase)
	if err != nil {
		return "", err
	}

	unlocked.ClearPrivateParams()
	return locked.Armor()
}

// GenerateKey generates a key of the given keyType ("rsa" or "x25519"), encrypts it, and returns an armored string.
// If keyType is "rsa", bits is the RSA bitsize of the key.
// If keyType is "x25519" bits is unused.
func GenerateKey(name, email string, passphrase []byte, keyType string, bits int) (string, error) {
	key, err :=  crypto.GenerateKey(name, email, keyType, bits)
	if err != nil {
		return "", err
	}

	locked, err := key.Lock(passphrase)
	if err != nil {
		return "", err
	}

	key.ClearPrivateParams()
	return locked.Armor()
}