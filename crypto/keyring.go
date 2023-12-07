package crypto

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/pkg/errors"
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
	Name  string `json:"name"`
	Email string `json:"email"`
}

// --- New keyrings

// NewKeyRing creates a new KeyRing, empty if key is nil.
func NewKeyRing(key *Key) (*KeyRing, error) {
	keyRing := &KeyRing{}
	var err error
	if key != nil {
		err = keyRing.AddKey(key)
	}
	return keyRing, err
}

// AddKey adds the given key to the keyring.
func (keyRing *KeyRing) AddKey(key *Key) error {
	if key.IsPrivate() {
		unlocked, err := key.IsUnlocked()
		if err != nil || !unlocked {
			return errors.New("gopenpgp: unable to add locked key to a keyring")
		}
	}

	keyRing.appendKey(key)
	return nil
}

// --- Extract keys from keyring

// GetKeys returns openpgp keys contained in this KeyRing.
// Not supported on go mobile clients.
func (keyRing *KeyRing) GetKeys() []*Key {
	keys := make([]*Key, keyRing.CountEntities())
	for i, entity := range keyRing.entities {
		keys[i] = &Key{entity}
	}
	return keys
}

// GetKey returns the n-th openpgp key contained in this KeyRing.
func (keyRing *KeyRing) GetKey(n int) (*Key, error) {
	if n >= keyRing.CountEntities() {
		return nil, errors.New("gopenpgp: out of bound when fetching key")
	}
	return &Key{keyRing.entities[n]}, nil
}

func (keyRing *KeyRing) signingEntities() ([]*openpgp.Entity, error) {
	var signEntity []*openpgp.Entity
	for _, e := range keyRing.entities {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil && !e.PrivateKey.Encrypted {
			signEntity = append(signEntity, e)
		} else {
			return nil, errors.New("gopenpgp: signing entity does not contain unencrypted private key")
		}
	}
	return signEntity, nil
}

// getEntities returns the internal EntityList if the key ring is not nil.
func (keyRing *KeyRing) getEntities() openpgp.EntityList {
	if keyRing == nil {
		return nil
	}
	return keyRing.entities
}

// --- Extract info from key

// CountEntities returns the number of entities in the keyring.
func (keyRing *KeyRing) CountEntities() int {
	if keyRing == nil {
		return 0
	}
	return len(keyRing.entities)
}

// CountDecryptionEntities returns the number of entities in the keyring.
// Takes the current time for checking the keys in unix time format.
// If the unix time is zero, time checks are ignored.
func (keyRing *KeyRing) CountDecryptionEntities(unixTime int64) int {
	var count int
	var checkTime time.Time
	if unixTime != 0 {
		checkTime = time.Unix(unixTime, 0)
	}
	for _, entity := range keyRing.entities {
		decryptionKeys := entity.DecryptionKeys(0, checkTime)
		count += len(decryptionKeys)
	}
	return count
}

// GetIdentities returns the list of identities associated with this key ring.
// Not supported on go-mobile clients use keyRing.GetIdentitiesJson() instead.
func (keyRing *KeyRing) GetIdentities() []*Identity {
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

// GetIdentitiesJson returns the list of identities associated with this key ring encoded as json.
// Returns nil if an encoding error occurs.
// Helper function for go-mobile clients.
func (keyRing *KeyRing) GetIdentitiesJson() []byte {
	identitiesJson, err := json.Marshal(keyRing.GetIdentities())
	if err != nil {
		return nil
	}
	return identitiesJson
}

// CanVerify returns true if any of the keys in the keyring can be used for verification.
func (keyRing *KeyRing) CanVerify(unixTime int64) bool {
	keys := keyRing.GetKeys()
	for _, key := range keys {
		if key.CanVerify(unixTime) {
			return true
		}
	}
	return false
}

// CanEncrypt returns true if any of the keys in the keyring can be used for encryption.
func (keyRing *KeyRing) CanEncrypt(unixTime int64) bool {
	keys := keyRing.GetKeys()
	for _, key := range keys {
		if key.CanEncrypt(unixTime) {
			return true
		}
	}
	return false
}

// GetKeyIDs returns array of IDs of keys in this KeyRing.
// Not supported on go-mobile clients.
func (keyRing *KeyRing) GetKeyIDs() []uint64 {
	var res = make([]uint64, len(keyRing.entities))
	for id, e := range keyRing.entities {
		res[id] = e.PrimaryKey.KeyId
	}
	return res
}

// GetHexKeyIDsJson returns an IDs of keys in this KeyRing as a json array.
// Key ids are encoded as hexadecimal and nil is returned if an error occurs.
// Helper function for go-mobile clients.
func (keyRing *KeyRing) GetHexKeyIDsJson() []byte {
	var res = make([]string, len(keyRing.entities))
	for id, e := range keyRing.entities {
		res[id] = keyIDToHex(e.PrimaryKey.KeyId)
	}
	keyIdsJson, err := json.Marshal(res)
	if err != nil {
		return nil
	}
	return keyIdsJson
}

// --- Filter keyrings

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
		for _, entity := range contactKeyRing.entities {
			hasExpired := false
			hasUnexpired := false
			for _, subkey := range entity.Subkeys {
				latestValid, err := subkey.LatestValidBindingSignature(now)
				if err != nil {
					hasExpired = true
				}
				if subkey.PublicKey.KeyExpired(latestValid, now) {
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
			keyRingCopy, err := contactKeyRing.Copy()
			if err != nil {
				return nil, err
			}

			filteredKeys = append(filteredKeys, keyRingCopy)
		} else if keyRingHasTotallyExpiredEntity {
			hasExpiredEntity = true
		}
	}

	if len(filteredKeys) == 0 && hasExpiredEntity {
		return filteredKeys, errors.New("gopenpgp: all contacts keys are expired")
	}

	return filteredKeys, nil
}

// FirstKey returns a KeyRing with only the first key of the original one.
func (keyRing *KeyRing) FirstKey() (*KeyRing, error) {
	if len(keyRing.entities) == 0 {
		return nil, errors.New("gopenpgp: No key available in this keyring")
	}
	newKeyRing := &KeyRing{}
	newKeyRing.entities = keyRing.entities[:1]

	return newKeyRing.Copy()
}

// Copy creates a deep copy of the keyring.
func (keyRing *KeyRing) Copy() (*KeyRing, error) {
	newKeyRing := &KeyRing{}

	entities := make([]*openpgp.Entity, len(keyRing.entities))
	for id, entity := range keyRing.entities {
		var buffer bytes.Buffer
		var err error

		if entity.PrivateKey == nil {
			err = entity.Serialize(&buffer)
		} else {
			err = entity.SerializePrivateWithoutSigning(&buffer, nil)
		}

		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to copy key: error in serializing entity")
		}

		bt := buffer.Bytes()
		entities[id], err = openpgp.ReadEntity(packet.NewReader(bytes.NewReader(bt)))

		if err != nil {
			return nil, errors.Wrap(err, "gopenpgp: unable to copy key: error in reading entity")
		}
	}
	newKeyRing.entities = entities
	newKeyRing.FirstKeyID = keyRing.FirstKeyID

	return newKeyRing, nil
}

func (keyRing *KeyRing) ClearPrivateParams() {
	for _, key := range keyRing.GetKeys() {
		key.ClearPrivateParams()
	}
}

// INTERNAL FUNCTIONS

// appendKey appends a key to the keyring.
func (keyRing *KeyRing) appendKey(key *Key) {
	keyRing.entities = append(keyRing.entities, key.entity)
}
