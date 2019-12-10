package crypto

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/pkg/errors"

	"golang.org/x/crypto/openpgp"
	xarmor "golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// Key contains a single private or public key
type Key struct {
	// PGP entities in this keyring.
	entity *openpgp.Entity
}

// --- Create Key object

// NewKeyFromArmoredReader reads an armored data into a key.
func NewKeyFromArmoredReader(r io.Reader) (key *Key, err error) {
	key = &Key{}
	err = key.readFrom(r, true)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// NewKeyFromReader reads an binary data into Key
func NewKeyFromReader(r io.Reader) (key *Key, err error) {
	key = &Key{}
	err = key.readFrom(r, false)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// NewKey creates a new key from the first key in the unarmored binary data
func NewKey(binKeys []byte) (key *Key, err error) {
	return NewKeyFromReader(bytes.NewReader(binKeys))
}

// NewKeyFromArmored creates a new key from the first key in an armored
func NewKeyFromArmored(armored string) (key *Key, err error) {
	return NewKeyFromArmoredReader(strings.NewReader(armored))
}

// GenerateRSAKeyWithPrimes generates a RSA key using the given primes.
func GenerateRSAKeyWithPrimes(
	name, email string,
	bits int,
	primeone, primetwo, primethree, primefour []byte,
) (*Key, error) {
	return generateKey(name, email, "rsa", bits, primeone, primetwo, primethree, primefour)
}

// GenerateKey generates a key of the given keyType ("rsa" or "x25519").
// If keyType is "rsa", bits is the RSA bitsize of the key.
// If keyType is "x25519" bits is unused.
func GenerateKey(name, email string, keyType string, bits int) (*Key, error) {
	return generateKey(name, email, keyType, bits, nil, nil, nil, nil)
}

// --- Operate on key

// Copy creates a copy of the key.
func (key *Key) Copy() (*Key, error) {
	serialized, err := key.Serialize()
	if err != nil {
		return nil, err
	}

	return NewKey(serialized)
}

// Lock locks a copy of the key.
func (key *Key) Lock(passphrase []byte) (*Key, error) {
	unlocked, err := key.IsUnlocked()
	if err != nil {
		return nil, err
	}

	if !unlocked {
		return nil, errors.New("gopenpgp: key is not unlocked")
	}

	lockedKey, err := key.Copy()
	if err != nil {
		return nil, err
	}

	err = lockedKey.entity.PrivateKey.Encrypt(passphrase)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in locking key")
	}

	for _, sub := range lockedKey.entity.Subkeys {
		if sub.PrivateKey != nil {
			if err := sub.PrivateKey.Encrypt(passphrase); err != nil {
				return nil, errors.Wrap(err, "gopenpgp: error in locking sub key")
			}
		}
	}

	locked, err := lockedKey.IsLocked()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("gopenpgp: unable to lock key")
	}

	return lockedKey, nil
}

// Unlock unlocks a copy of the key
func (key *Key) Unlock(passphrase []byte) (*Key, error) {
	isLocked, err := key.IsLocked()
	if err != nil {
		return nil, err
	}

	if !isLocked {
		return nil, errors.New("gopenpgp: key is not locked")
	}

	unlockedKey, err := key.Copy()
	if err != nil {
		return nil, err
	}

	err = unlockedKey.entity.PrivateKey.Decrypt(passphrase)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in unlocking key")
	}

	for _, sub := range unlockedKey.entity.Subkeys {
		if sub.PrivateKey != nil {
			if err := sub.PrivateKey.Decrypt(passphrase); err != nil {
				return nil, errors.Wrap(err, "gopenpgp: error in unlocking sub key")
			}
		}
	}

	isUnlocked, err := unlockedKey.IsUnlocked()
	if err != nil {
		return nil, err
	}
	if !isUnlocked {
		return nil, errors.New("gopenpgp: unable to unlock key")
	}

	return unlockedKey, nil
}

// --- Export key

func (key *Key) Serialize() ([]byte, error) {
	var buffer bytes.Buffer
	var err error

	if key.entity.PrivateKey == nil {
		err = key.entity.Serialize(&buffer)
	} else {
		err = key.entity.SerializePrivateNoSign(&buffer, nil)
	}

	return buffer.Bytes(), err
}

func (key *Key) Armor() (string, error) {
	serialized, err := key.Serialize()
	if err != nil {
		return "", err
	}

	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// GetArmoredPublicKey returns the armored public keys from this keyring.
func (key *Key) GetArmoredPublicKey() (s string, err error) {
	var outBuf bytes.Buffer
	aw, err := xarmor.Encode(&outBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}

	if err = key.entity.Serialize(aw); err != nil {
		_ = aw.Close()
		return "", err
	}

	err = aw.Close()
	return outBuf.String(), err
}

// GetPublicKey returns the unarmored public keys from this keyring.
func (key *Key) GetPublicKey() (b []byte, err error) {
	var outBuf bytes.Buffer
	if err = key.entity.Serialize(&outBuf); err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}

// --- Key object properties

// IsExpired checks whether the key is expired.
func (key *Key) IsExpired() bool {
	_, ok := key.entity.EncryptionKey(getNow())
	return !ok
}

// IsPrivate returns true if the key is private
func (key *Key) IsPrivate() bool {
	return key.entity.PrivateKey != nil
}

// IsLocked checks if a private key is locked
func (key *Key) IsLocked() (bool, error) {
	if key.entity.PrivateKey == nil {
		return true, errors.New("gopenpgp: a public key cannot be locked")
	}

	for _, sub := range key.entity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
			return false, nil
		}
	}

	return key.entity.PrivateKey.Encrypted, nil
}

// IsUnlocked checks if a private key is unlocked
func (key *Key) IsUnlocked() (bool, error) {
	if key.entity.PrivateKey == nil {
		return true, errors.New("gopenpgp: a public key cannot be unlocked")
	}

	for _, sub := range key.entity.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			return false, nil
		}
	}

	return !key.entity.PrivateKey.Encrypted, nil
}

// Check verifies if the public keys match the private key parameters by signing and verifying
func (key *Key) Check() (bool, error) {
	var err error
	testSign := bytes.Repeat([]byte{0x01}, 64)
	testReader := bytes.NewReader(testSign)

	if !key.IsPrivate() {
		return false, errors.New("gopenpgp: can check only private key")
	}

	var signBuf bytes.Buffer

	if err = openpgp.DetachSign(&signBuf, key.entity, testReader, nil); err != nil {
		return false, errors.New("gopenpgp: unable to sign with key")
	}

	testReader = bytes.NewReader(testSign)
	signer, err := openpgp.CheckDetachedSignature(openpgp.EntityList{key.entity}, testReader, &signBuf, nil)

	if signer == nil || err != nil {
		return false, nil
	}

	return true, nil
}

// PrintFingerprints is a debug helper function that prints the key and subkey fingerprints.
func (key *Key) PrintFingerprints() {
	for _, subKey := range key.entity.Subkeys {
		if !subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications {
			fmt.Println("SubKey:" + hex.EncodeToString(subKey.PublicKey.Fingerprint[:]))
		}
	}
	fmt.Println("PrimaryKey:" + hex.EncodeToString(key.entity.PrimaryKey.Fingerprint[:]))
}

// GetID returns the key ID
func (key *Key) GetID() string {
	return "0x" + strconv.FormatUint(key.entity.PrimaryKey.KeyId, 16)
}

// GetFingerprint gets the fingerprint from the key
func (key *Key) GetFingerprint() string {
	return hex.EncodeToString(key.entity.PrimaryKey.Fingerprint[:])
}

// --- Internal methods

// readFrom reads unarmored and armored keys from r and adds them to the keyring.
func (key *Key) readFrom(r io.Reader, armored bool) error {
	var err error
	var entities openpgp.EntityList
	if armored {
		entities, err = openpgp.ReadArmoredKeyRing(r)
	} else {
		entities, err = openpgp.ReadKeyRing(r)
	}
	if err != nil {
		return err
	}

	if len(entities) > 1 {
		return errors.New("gopenpgp: the key contains too many entities")
	}

	if len(entities) == 0 {
		return errors.New("gopenpgp: the key does not contain any entity")
	}

	key.entity = entities[0]
	return nil
}

func generateKey(
	name, email string,
	keyType string,
	bits int,
	prime1, prime2, prime3, prime4 []byte,
) (*Key, error) {
	if len(email) == 0 {
		return nil, errors.New("gopenpgp: invalid email format")
	}

	if len(name) == 0 {
		return nil, errors.New("gopenpgp: invalid name format")
	}

	comments := ""

	cfg := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       bits,
		Time:          getTimeGenerator(),
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	if keyType == "x25519" {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	}

	if prime1 != nil && prime2 != nil && prime3 != nil && prime4 != nil {
		var bigPrimes [4]*big.Int
		bigPrimes[0] = new(big.Int)
		bigPrimes[0].SetBytes(prime1)
		bigPrimes[1] = new(big.Int)
		bigPrimes[1].SetBytes(prime2)
		bigPrimes[2] = new(big.Int)
		bigPrimes[2].SetBytes(prime3)
		bigPrimes[3] = new(big.Int)
		bigPrimes[3].SetBytes(prime4)

		cfg.RSAPrimes = bigPrimes[:]
	}

	newEntity, err := openpgp.NewEntity(name, comments, email, cfg)
	if err != nil {
		return nil, err
	}

	if err := newEntity.SelfSign(nil); err != nil {
		return nil, err
	}

	if newEntity.PrivateKey == nil {
		return nil, errors.New("gopenpgp: error in generating private key")
	}

	return &Key{newEntity}, nil
}
