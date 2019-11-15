package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	xrsa "golang.org/x/crypto/rsa"
	"io"
	"time"

	armorUtils "github.com/ProtonMail/gopenpgp/armor"
)

// KeyRing contains multiple private and public keys.
type KeyRing struct {
	// PGP entities in this keyring.
	entities openpgp.EntityList

	// FirstKeyID as obtained from API to match salt
	FirstKeyID string
}

// Identity contains the name and the email of a key holder.
type Identity struct {
	Name  string
	Email string
}

// GetEntities returns openpgp entities contained in this KeyRing.
func (keyRing *KeyRing) GetEntities() openpgp.EntityList {
	return keyRing.entities
}

// GetSigningEntity returns first private unlocked signing entity from keyring.
func (keyRing *KeyRing) GetSigningEntity() (*openpgp.Entity, error) {
	var signEntity *openpgp.Entity

	for _, e := range keyRing.entities {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			if !e.PrivateKey.Encrypted {
				signEntity = e
				break
			}
		}
	}
	if signEntity == nil {
		err := errors.New("gopenpgp: cannot sign message, unable to unlock signer key")
		return signEntity, err
	}

	return signEntity, nil
}

// WriteArmoredPublicKey outputs armored public keys from the keyring to w.
func (keyRing *KeyRing) WriteArmoredPublicKey(w io.Writer) (err error) {
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}

	for _, e := range keyRing.entities {
		if err = e.Serialize(aw); err != nil {
			aw.Close()
			return
		}
	}

	err = aw.Close()
	return
}

// GetArmoredPublicKey returns the armored public keys from this keyring.
func (keyRing *KeyRing) GetArmoredPublicKey() (s string, err error) {
	b := &bytes.Buffer{}
	if err = keyRing.WriteArmoredPublicKey(b); err != nil {
		return
	}

	s = b.String()
	return
}

// WritePublicKey outputs unarmored public keys from the keyring to w.
func (keyRing *KeyRing) WritePublicKey(w io.Writer) (err error) {
	for _, e := range keyRing.entities {
		if err = e.Serialize(w); err != nil {
			return
		}
	}

	return
}

// GetPublicKey returns the unarmored public keys from this keyring.
func (keyRing *KeyRing) GetPublicKey() (b []byte, err error) {
	var outBuf bytes.Buffer
	if err = keyRing.WritePublicKey(&outBuf); err != nil {
		return
	}

	b = outBuf.Bytes()
	return
}

// GetFingerprint gets the fingerprint from the keyring.
func (keyRing *KeyRing) GetFingerprint() (string, error) {
	for _, entity := range keyRing.entities {
		fp := entity.PrimaryKey.Fingerprint
		return hex.EncodeToString(fp[:]), nil
	}
	return "", errors.New("gopenpgp: can not find public key")
}

// CountEntities returns the number of entities in the keyring
func (keyRing *KeyRing) CountEntities() int {
	return len(keyRing.GetEntities())
}

// CountDecryptionEntities returns the number of entities in the keyring
func (keyRing *KeyRing) CountDecryptionEntities() int {
	return len(keyRing.GetEntities().DecryptionKeys())
}

// check verifies if the given passphrases fully unlock a locked keyring, and optionally if the public keys match the
// private key parameters
func (keyRing *KeyRing) check(passphrases [][]byte, verifyPrivate bool) (bool, error) {
	if !keyRing.IsLocked() {
		return false, errors.New("gopenpgp: keyring is already unlocked")
	}

	unlocked, err := keyRing.Copy()
	if err != nil {
		return false, err
	}

	err = unlocked.unlock(passphrases)

	if err != nil || !unlocked.IsUnlocked() {
		return false, nil
	}

	if !verifyPrivate {
		return true, nil
	}

	testSign := []byte("7fJFAX8csfm7QQ3Q0BxDLe8SnCEU8dZO")
	testReader := bytes.NewReader(testSign)

	var validKeys = 0
	for _, entity := range unlocked.GetEntities() {
		if entity.PrivateKey != nil {
			var signBuf bytes.Buffer

			if err = openpgp.DetachSign(&signBuf, entity, testReader, nil); err != nil {
				continue
			}

			testReader = bytes.NewReader(testSign)
			signer, err := openpgp.CheckDetachedSignature(openpgp.EntityList{ entity }, testReader, &signBuf, nil)

			if signer == nil || err != nil {
				return false, nil
			}
			validKeys++
		}
	}

	if validKeys == 0 {
		return false, errors.New("gopenpgp: unable to find any valid key")
	}
	return true, nil
}

// CheckIntegrity checks if the given passphrases fully unlock a locked keyring, and if the public keys is actually
// derived from the private keys
func (keyRing *KeyRing) CheckIntegrity(passphrases [][]byte) (bool, error) {
	return keyRing.check(passphrases, true)
}

// CheckPassphrases checks if the given passphrases fully unlock a locked keyring.
func (keyRing *KeyRing) CheckPassphrases(passphrases [][]byte) (bool, error) {
	return keyRing.check(passphrases, false)
}

// Unlock fully unlocks a copy of the keyring.
func (keyRing *KeyRing) Unlock(passphrases [][]byte) (*KeyRing, error) {
	if !keyRing.IsLocked() {
		return nil, errors.New("gopenpgp: keyring is already unlocked")
	}

	unlocked, err := keyRing.Copy()
	if err != nil {
		return nil, err
	}

	err = unlocked.unlock(passphrases)

	if err != nil || !unlocked.IsUnlocked() {
		return nil, errors.New("gopenpgp: unable to unlock keyring")
	}

	return unlocked, nil
}

// Lock fully locks a copy of the keyring.
func (keyRing *KeyRing) Lock(passphrase []byte) (*KeyRing, error) {
	if !keyRing.IsUnlocked() {
		return nil, errors.New("gopenpgp: keyring is not unlocked")
	}

	locked, err := keyRing.Copy()
	if err != nil {
		return nil, err
	}

	err = locked.lock(passphrase)

	if err != nil || !locked.IsLocked() {
		return nil, errors.New("gopenpgp: unable to fully lock keyring")
	}

	return locked, nil
}

// Copy creates a deep copy of the keyring
func (keyRing *KeyRing) Copy() (*KeyRing, error) {
	newKeyRing := &KeyRing{}

	entities := make([]*openpgp.Entity, len(keyRing.entities))
	for id, entity := range keyRing.entities {
		var buffer bytes.Buffer
		var err error

		if entity.PrivateKey == nil {
			err = entity.Serialize(&buffer)
		} else {
			err = entity.SerializePrivateNoSign(&buffer, nil)
		}

		if err != nil {
			return nil, errors.New("gopenpgp: unable to copy key: error in serializing entity: " + err.Error())
		}

		bt := buffer.Bytes()
		entities[id], err = openpgp.ReadEntity(packet.NewReader(bytes.NewReader(bt)))

		if err != nil {
			return nil, errors.New("gopenpgp: unable to copy key: error in reading entity: " + err.Error())
		}
	}
	newKeyRing.entities = entities
	newKeyRing.FirstKeyID = keyRing.FirstKeyID

	return newKeyRing, nil
}

// IsLocked checks if a keyring is fully locked
func (keyRing *KeyRing) IsLocked() bool {
	for _, entity := range keyRing.entities {
		if entity.PrivateKey.Encrypted {
			continue // Key still encrypted
		}
		return false
	}
	return true
}

// IsUnlocked checks if a keyring is fully unlocked
func (keyRing *KeyRing) IsUnlocked() bool {
	for _, entity := range keyRing.entities {
		if !entity.PrivateKey.Encrypted {
			continue // Key already decrypted
		}
		return false
	}
	return true
}

// ReadFrom reads unarmored and armored keys from r and adds them to the keyring.
func (keyRing *KeyRing) ReadFrom(r io.Reader, armored bool) error {
	var err error
	var entities openpgp.EntityList
	if armored {
		entities, err = openpgp.ReadArmoredKeyRing(r)
	} else {
		entities, err = openpgp.ReadKeyRing(r)
	}
	for _, entity := range entities {
		if entity.PrivateKey != nil {
			switch entity.PrivateKey.PrivateKey.(type) {
			// TODO: type mismatch after crypto lib update, fix this:
			case *rsa.PrivateKey:
				entity.PrimaryKey = packet.NewRSAPublicKey(
					time.Now(),
					entity.PrivateKey.PrivateKey.(*rsa.PrivateKey).Public().(*xrsa.PublicKey))

			case *ecdsa.PrivateKey:
				entity.PrimaryKey = packet.NewECDSAPublicKey(
					time.Now(),
					entity.PrivateKey.PrivateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey))
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				switch subkey.PrivateKey.PrivateKey.(type) {
				case *rsa.PrivateKey:
					subkey.PublicKey = packet.NewRSAPublicKey(
						time.Now(),
						subkey.PrivateKey.PrivateKey.(*rsa.PrivateKey).Public().(*xrsa.PublicKey))

				case *ecdsa.PrivateKey:
					subkey.PublicKey = packet.NewECDSAPublicKey(
						time.Now(),
						subkey.PrivateKey.PrivateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey))
				}
			}
		}
	}
	if err != nil {
		return err
	}

	if len(entities) == 0 {
		return errors.New("gopenpgp: key ring doesn't contain any key")
	}

	keyRing.entities = append(keyRing.entities, entities...)
	return nil
}

// BuildKeyRing reads keyring from binary data
func BuildKeyRing(binKeys []byte) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	entriesReader := bytes.NewReader(binKeys)
	err = keyRing.ReadFrom(entriesReader, false)

	return
}

// BuildKeyRingNoError does not return error on fail
func BuildKeyRingNoError(binKeys []byte) (keyRing *KeyRing) {
	keyRing, _ = BuildKeyRing(binKeys)
	return
}

// BuildKeyRingArmored reads armored string and returns keyring
func BuildKeyRingArmored(key string) (keyRing *KeyRing, err error) {
	keyRaw, err := armorUtils.Unarmor(key)
	if err != nil {
		return nil, err
	}
	keyReader := bytes.NewReader(keyRaw)
	keyEntries, err := openpgp.ReadKeyRing(keyReader)
	return &KeyRing{entities: keyEntries}, err
}

// Identities returns the list of identities associated with this key ring.
func (keyRing *KeyRing) Identities() []*Identity {
	var identities []*Identity
	for _, e := range keyRing.entities {
		for _, id := range e.Identities {
			identities = append(identities, &Identity{
				Name:  id.UserId.Name,
				Email: id.UserId.Email,
			})
		}
	}
	return identities
}

// KeyIds returns array of IDs of keys in this KeyRing.
func (keyRing *KeyRing) KeyIds() []uint64 {
	var res []uint64
	for _, e := range keyRing.entities {
		res = append(res, e.PrimaryKey.KeyId)
	}
	return res
}

// ReadArmoredKeyRing reads an armored data into keyring.
func ReadArmoredKeyRing(r io.Reader) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	err = keyRing.ReadFrom(r, true)
	return
}

// ReadKeyRing reads an binary data into keyring.
func ReadKeyRing(r io.Reader) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	err = keyRing.ReadFrom(r, false)
	return
}

// FilterExpiredKeys takes a given KeyRing list and it returns only those
// KeyRings which contain at least, one unexpired Key. It returns only unexpired
// parts of these KeyRings.
func FilterExpiredKeys(contactKeys []*KeyRing) (filteredKeys []*KeyRing, err error) {
	now := time.Now()
	hasExpiredEntity := false
	filteredKeys = make([]*KeyRing, 0)

	for _, contactKeyRing := range contactKeys {
		keyRingHasUnexpiredEntity := false
		keyRingHasTotallyExpiredEntity := false
		for _, entity := range contactKeyRing.GetEntities() {
			hasExpired := false
			hasUnexpired := false
			for _, subkey := range entity.Subkeys {
				if subkey.PublicKey.KeyExpired(subkey.Sig, now) {
					hasExpired = true
				} else {
					hasUnexpired = true
				}
			}
			if hasExpired && !hasUnexpired {
				keyRingHasTotallyExpiredEntity = true
			} else if hasUnexpired {
				keyRingHasUnexpiredEntity = true
			}
		}
		if keyRingHasUnexpiredEntity {
			filteredKeys = append(filteredKeys, contactKeyRing)
		} else if keyRingHasTotallyExpiredEntity {
			hasExpiredEntity = true
		}
	}

	if len(filteredKeys) == 0 && hasExpiredEntity {
		return filteredKeys, errors.New("gopenpgp: all contacts keys are expired")
	}

	return filteredKeys, nil
}

// FirstKey returns a KeyRing with only the first key of the original one
func (keyRing *KeyRing) FirstKey() (*KeyRing, error) {
	if len(keyRing.entities) == 0 {
		return nil, errors.New("gopenpgp: No key available in this keyring")
	}
	newKeyRing := &KeyRing{}
	newKeyRing.entities = keyRing.entities[:1]

	return newKeyRing.Copy()
}

// unlock tries to unlock as many keys as possible with the given passwords. Note
// that keyrings can contain keys locked with different passwords, and thus
// err == nil does not mean that all keys have been successfully decrypted,
// rather that all keys are well-formed
func (keyRing *KeyRing) unlock(passphrases [][]byte) error {
	// Build a list of keys to decrypt
	keys := keyRing.getPrivatePackets()

	if len(keys) == 0 {
		return errors.New("gopenpgp: cannot unlock key ring, no private key available")
	}

	for _, passphrase := range passphrases {
		for _, key := range keys {
			if key.Encrypted {
				_ = key.Decrypt(passphrase)
			}
		}
	}

	return nil
}

// lock encrypts all unlocked keys with the given password. Note that keyrings can contain one or more keys.
func (keyRing *KeyRing) lock(passphrase []byte) error {
	// Build a list of keys to encrypt
	keys := keyRing.getPrivatePackets()

	if len(keys) == 0 {
		return errors.New("gopenpgp: cannot lock key ring, no private key available")
	}

	for _, key := range keys {
		if !key.Encrypted {
			_ = key.Encrypt(passphrase)
		}
	}

	return nil
}

func (keyRing *KeyRing) getPrivatePackets() (keys []*packet.PrivateKey) {
	// Build a list of private packets
	for _, e := range keyRing.entities {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			keys = append(keys, e.PrivateKey)
		}

		// Entity.Subkeys can be used for encryption
		for _, subKey := range e.Subkeys {
			if subKey.PrivateKey != nil && (!subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage ||
				subKey.Sig.FlagEncryptCommunications) {

				keys = append(keys, subKey.PrivateKey)
			}
		}
	}
	return keys
}
