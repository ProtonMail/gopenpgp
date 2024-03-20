package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	packet "github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/pkg/errors"
)

// Key contains a single private or public key.
type Key struct {
	// PGP entities in this keyring.
	entity *openpgp.Entity
}

type KeyEncryptionProfile interface {
	KeyEncryptionConfig() *packet.Config
}

// --- Create Key object

// NewKeyFromReader reads binary or armored data into a Key object.
func NewKeyFromReader(r io.Reader) (key *Key, err error) {
	return NewKeyFromReaderExplicit(r, Auto)
}

// NewKeyFromReaderExplicit reads binary or armored data into a Key object.
// Allows to set the encoding explicitly to avoid the armor check.
func NewKeyFromReaderExplicit(r io.Reader, encoding int8) (key *Key, err error) {
	var armored bool
	key = &Key{}
	switch encoding {
	case Auto:
		r, armored = armor.IsPGPArmored(r)
	case Armor:
		armored = true
	case Bytes:
		armored = false
	default:
		return nil, errors.New("gopenpgp: encoding is not supported")
	}
	err = key.readFrom(r, armored)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// NewKey creates a new key from the first key in the unarmored or armored binary data.
// Clones the binKeys data for go-mobile compatibility.
func NewKey(binKeys []byte) (key *Key, err error) {
	return NewKeyFromReader(bytes.NewReader(clone(binKeys)))
}

// NewKeyWithCloneFlag creates a new key from the first key in the unarmored or armored binary data.
func NewKeyWithCloneFlag(binKeys []byte, clone bool) (key *Key, err error) {
	if clone {
		return NewKey(binKeys)
	}
	return NewKeyFromReader(bytes.NewReader(binKeys))
}

// NewKeyFromArmored creates a new key from the first key in an armored string.
func NewKeyFromArmored(armored string) (key *Key, err error) {
	return NewKeyFromReader(strings.NewReader(armored))
}

// NewPrivateKeyFromArmored creates a new secret key from the first key in an armored string
// and unlocks it with the password.
func NewPrivateKeyFromArmored(armored string, password []byte) (key *Key, err error) {
	lockedKey, err := NewKeyFromArmored(armored)
	if err != nil {
		return
	}
	isLocked, err := lockedKey.IsLocked()
	if err != nil {
		return
	}
	if isLocked {
		key, err = lockedKey.Unlock(password)
		if err != nil {
			return nil, err
		}
	} else {
		key = lockedKey
	}
	return
}

// NewKeyFromEntity creates a key from the provided go-crypto/openpgp entity.
func NewKeyFromEntity(entity *openpgp.Entity) (*Key, error) {
	if entity == nil {
		return nil, errors.New("gopenpgp: nil entity provided")
	}
	return &Key{entity: entity}, nil
}

// generateKey generates a key with the given key-generation profile and security-level.
func generateKey(name, email string, clock Clock, profile KeyGenerationProfile, securityLevel int8, lifeTimeSec uint32) (*Key, error) {
	config := profile.KeyGenerationConfig(securityLevel)
	config.Time = NewConstantClock(clock().Unix())
	config.KeyLifetimeSecs = lifeTimeSec
	return generateKeyWithConfig(name, email, "", config)
}

// --- Operate on key

// Copy creates a deep copy of the key.
func (key *Key) Copy() (*Key, error) {
	serialized, err := key.Serialize()
	if err != nil {
		return nil, err
	}

	return NewKey(serialized)
}

// lock locks a copy of the key.
func (key *Key) lock(passphrase []byte, profile KeyEncryptionProfile) (*Key, error) {
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

	if passphrase == nil {
		return lockedKey, nil
	}

	err = lockedKey.entity.EncryptPrivateKeys(passphrase, profile.KeyEncryptionConfig())
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in locking key")
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

// Unlock unlocks a copy of the key.
func (key *Key) Unlock(passphrase []byte) (*Key, error) {
	isLocked, err := key.IsLocked()
	if err != nil {
		return nil, err
	}

	if !isLocked {
		if passphrase == nil {
			return key.Copy()
		}
		return nil, errors.New("gopenpgp: key is not locked")
	}

	unlockedKey, err := key.Copy()
	if err != nil {
		return nil, err
	}

	err = unlockedKey.entity.DecryptPrivateKeys(passphrase)
	if err != nil {
		return nil, errors.New("gopenpgp: error in unlocking key")
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
		err = key.entity.SerializePrivateWithoutSigning(&buffer, nil)
	}

	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in serializing key")
	}

	return buffer.Bytes(), nil
}

// Armor returns the armored key as a string with default gopenpgp headers.
func (key *Key) Armor() (string, error) {
	serialized, err := key.Serialize()
	if err != nil {
		return "", err
	}

	if key.IsPrivate() {
		return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
	}

	return armor.ArmorWithType(serialized, constants.PublicKeyHeader)
}

// ArmorWithCustomHeaders returns the armored key as a string, with
// the given headers. Empty parameters are omitted from the headers.
func (key *Key) ArmorWithCustomHeaders(comment, version string) (string, error) {
	serialized, err := key.Serialize()
	if err != nil {
		return "", err
	}

	return armor.ArmorWithTypeAndCustomHeaders(serialized, constants.PrivateKeyHeader, version, comment)
}

// GetArmoredPublicKey returns the armored public keys from this keyring.
func (key *Key) GetArmoredPublicKey() (s string, err error) {
	serialized, err := key.GetPublicKey()
	if err != nil {
		return "", err
	}

	return armor.ArmorWithType(serialized, constants.PublicKeyHeader)
}

// GetArmoredPublicKeyWithCustomHeaders returns the armored public key as a string, with
// the given headers. Empty parameters are omitted from the headers.
func (key *Key) GetArmoredPublicKeyWithCustomHeaders(comment, version string) (string, error) {
	serialized, err := key.GetPublicKey()
	if err != nil {
		return "", err
	}

	return armor.ArmorWithTypeAndCustomHeaders(serialized, constants.PublicKeyHeader, version, comment)
}

// GetPublicKey returns the unarmored public keys from this keyring.
func (key *Key) GetPublicKey() (b []byte, err error) {
	var outBuf bytes.Buffer
	if err = key.entity.Serialize(&outBuf); err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in serializing public key")
	}

	return outBuf.Bytes(), nil
}

// --- Key object properties

// CanVerify returns true if any of the subkeys can be used for verification.
func (key *Key) CanVerify(unixTime int64) bool {
	_, canVerify := key.entity.SigningKey(time.Unix(unixTime, 0), nil)
	return canVerify
}

// CanEncrypt returns true if any of the subkeys can be used for encryption.
func (key *Key) CanEncrypt(unixTime int64) bool {
	_, canEncrypt := key.entity.EncryptionKey(time.Unix(unixTime, 0), nil)
	return canEncrypt
}

// IsExpired checks whether the key is expired.
func (key *Key) IsExpired(unixTime int64) bool {
	current := time.Unix(unixTime, 0)
	sig, err := key.entity.PrimarySelfSignature(time.Time{})
	if err != nil {
		return true
	}
	return key.entity.PrimaryKey.KeyExpired(sig, current) || // primary key has expired
		sig.SigExpired(current) // user ID self-signature has expired
}

// IsRevoked checks whether the key or the primary identity has a valid revocation signature.
func (key *Key) IsRevoked(unixTime int64) bool {
	current := time.Unix(unixTime, 0)
	return key.entity.Revoked(current)
}

// IsPrivate returns true if the key is private.
func (key *Key) IsPrivate() bool {
	return key.entity.PrivateKey != nil
}

// IsLocked checks if a private key is locked.
func (key *Key) IsLocked() (bool, error) {
	if key.entity.PrivateKey == nil {
		return false, errors.New("gopenpgp: a public key cannot be locked")
	}

	encryptedKeys := 0

	for _, sub := range key.entity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() && sub.PrivateKey.Encrypted {
			encryptedKeys++
		}
	}

	if key.entity.PrivateKey.Encrypted {
		encryptedKeys++
	}

	return encryptedKeys > 0, nil
}

// IsUnlocked checks if a private key is unlocked.
func (key *Key) IsUnlocked() (bool, error) {
	if key.entity.PrivateKey == nil {
		return true, errors.New("gopenpgp: a public key cannot be unlocked")
	}

	encryptedKeys := 0

	for _, sub := range key.entity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() && sub.PrivateKey.Encrypted {
			encryptedKeys++
		}
	}

	if key.entity.PrivateKey.Encrypted {
		encryptedKeys++
	}

	return encryptedKeys == 0, nil
}

// Check verifies if the public keys match the private key parameters by
// signing and verifying.
// Deprecated: all keys are now checked on parsing.
func (key *Key) Check() (bool, error) {
	return true, nil
}

// PrintFingerprints is a debug helper function that prints the key and subkey fingerprints.
func (key *Key) PrintFingerprints() {
	for _, subKey := range key.entity.Subkeys {
		binding, err := subKey.LatestValidBindingSignature(time.Time{})
		if err != nil {
			continue
		}
		if !binding.FlagsValid || binding.FlagEncryptStorage || binding.FlagEncryptCommunications {
			fmt.Println("SubKey:" + hex.EncodeToString(subKey.PublicKey.Fingerprint))
		}
	}
	fmt.Println("PrimaryKey:" + hex.EncodeToString(key.entity.PrimaryKey.Fingerprint))
}

// GetHexKeyID returns the key ID, hex encoded as a string.
func (key *Key) GetHexKeyID() string {
	return keyIDToHex(key.GetKeyID())
}

// GetKeyID returns the key ID, encoded as 8-byte int.
// Does not work for go-mobile clients, use GetHexKeyID instead.
func (key *Key) GetKeyID() uint64 {
	return key.entity.PrimaryKey.KeyId
}

// GetFingerprint gets the fingerprint from the key.
func (key *Key) GetFingerprint() string {
	return hex.EncodeToString(key.entity.PrimaryKey.Fingerprint)
}

// GetFingerprintBytes gets the fingerprint from the key as a byte slice.
func (key *Key) GetFingerprintBytes() []byte {
	return key.entity.PrimaryKey.Fingerprint
}

// GetSHA256Fingerprints computes the SHA256 fingerprints of the key and subkeys.
func (key *Key) GetSHA256Fingerprints() (fingerprints []string) {
	fingerprints = append(fingerprints, hex.EncodeToString(getSHA256FingerprintBytes(key.entity.PrimaryKey)))
	for _, sub := range key.entity.Subkeys {
		fingerprints = append(fingerprints, hex.EncodeToString(getSHA256FingerprintBytes(sub.PublicKey)))
	}
	return
}

// GetJsonSHA256Fingerprints returns the SHA256 fingerprints of key and subkeys
// encoded in JSON, for gomobile clients that cannot handle arrays.
func (key *Key) GetJsonSHA256Fingerprints() ([]byte, error) {
	return json.Marshal(key.GetSHA256Fingerprints())
}

// GetEntity gets x/crypto Entity object.
// Not supported on go-mobile clients.
func (key *Key) GetEntity() *openpgp.Entity {
	return key.entity
}

// GetVersion returns the OpenPGP key packet version of this key.
func (key *Key) GetVersion() int {
	return key.entity.PrimaryKey.Version
}

// ToPublic returns the corresponding public key of the given private key.
func (key *Key) ToPublic() (publicKey *Key, err error) {
	if !key.IsPrivate() {
		return nil, errors.New("gopenpgp: key is already public")
	}

	publicKey, err = key.Copy()
	if err != nil {
		return nil, err
	}

	publicKey.ClearPrivateParams()
	return
}

// --- Internal methods

// getSHA256FingerprintBytes computes the SHA256 fingerprint of a public key
// object.
func getSHA256FingerprintBytes(pk *packet.PublicKey) []byte {
	fingerPrint := sha256.New()

	// Hashing can't return an error, and has already been done when parsing the key,
	// hence the error is nil
	_ = pk.SerializeForHash(fingerPrint)
	return fingerPrint.Sum(nil)
}

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
		return errors.Wrap(err, "gopenpgp: error in reading key ring")
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

func generateKeyWithConfig(
	name, email, comments string,
	config *packet.Config,
) (*Key, error) {
	if len(email) == 0 && len(name) == 0 {
		return nil, errors.New("gopenpgp: neither name nor email set.")
	}
	newEntity, err := openpgp.NewEntity(name, comments, email, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopengpp: error in encoding new entity")
	}

	if newEntity.PrivateKey == nil {
		return nil, errors.New("gopenpgp: error in generating private key")
	}

	return NewKeyFromEntity(newEntity)
}

// keyIDToHex casts a keyID to hex with the correct padding.
func keyIDToHex(keyID uint64) string {
	return fmt.Sprintf("%016v", strconv.FormatUint(keyID, 16))
}
