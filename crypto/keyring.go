package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	xrsa "golang.org/x/crypto/rsa"

	armorUtils "github.com/ProtonMail/gopenpgp/armor"
)

// KeyRing contains multiple private and public keys.
type KeyRing struct {
	// PGP entities in this keyring.
	entities openpgp.EntityList

	// FirstKeyID as obtained from API to match salt
	FirstKeyID string
}

// A keypair contains a private key and a public key.
type pgpKeyObject struct {
	ID          string
	Version     int
	Flags       int
	PrivateKey  string
	Primary     int
	Token       *string `json:",omitempty"`
	Signature   *string `json:",omitempty"`
}

// PrivateKeyReader
func (ko *pgpKeyObject) PrivateKeyReader() io.Reader {
	return strings.NewReader(ko.PrivateKey)
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

// Unlock tries to unlock as many keys as possible with the following password. Note
// that keyrings can contain keys locked with different passwords, and thus
// err == nil does not mean that all keys have been successfully decrypted.
// If err != nil, the password is wrong for every key, and err is the last error
// encountered.
func (keyRing *KeyRing) Unlock(passphrase []byte) error {
	// Build a list of keys to decrypt
	var keys []*packet.PrivateKey
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

	if len(keys) == 0 {
		return errors.New("gopenpgp: cannot unlock key ring, no private key available")
	}

	var err error
	var n int
	for _, key := range keys {
		if !key.Encrypted {
			continue // Key already decrypted
		}

		if err = key.Decrypt(passphrase); err == nil {
			n++
		}
	}

	if n == 0 {
		return err
	}
	return nil
}

// UnlockWithPassphrase is a wrapper for Unlock that uses strings
func (keyRing *KeyRing) UnlockWithPassphrase(passphrase string) error {
	return keyRing.Unlock([]byte(passphrase))
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
	return "", errors.New("can't find public key")
}

// CheckPassphrase checks if private key passphrase is correct for every sub key.
func (keyRing *KeyRing) CheckPassphrase(passphrase string) bool {
	var keys []*packet.PrivateKey

	for _, entity := range keyRing.entities {
		keys = append(keys, entity.PrivateKey)
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

	return n != 0
}

// readFrom reads unarmored and armored keys from r and adds them to the keyring.
func (keyRing *KeyRing) readFrom(r io.Reader, armored bool) error {
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
func (pgp *GopenPGP) BuildKeyRing(binKeys []byte) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	entriesReader := bytes.NewReader(binKeys)
	err = keyRing.readFrom(entriesReader, false)

	return
}

// BuildKeyRingNoError does not return error on fail
func (pgp *GopenPGP) BuildKeyRingNoError(binKeys []byte) (keyRing *KeyRing) {
	keyRing, _ = pgp.BuildKeyRing(binKeys)
	return
}

// BuildKeyRingArmored reads armored string and returns keyring
func (pgp *GopenPGP) BuildKeyRingArmored(key string) (keyRing *KeyRing, err error) {
	keyRaw, err := armorUtils.Unarmor(key)
	if err != nil {
		return nil, err
	}
	keyReader := bytes.NewReader(keyRaw)
	keyEntries, err := openpgp.ReadKeyRing(keyReader)
	return &KeyRing{entities: keyEntries}, err
}

// ReadFromJSON reads multiple keys from a json array and fills the keyring
func (keyRing *KeyRing) ReadFromJSON(jsonData []byte) (err error) {
	keyObjs, err := unmarshalJSON(jsonData)
	if err != nil {
		return err
	}

	return keyRing.newKeyRingFromPGPKeyObject(keyObjs)
}

// UnlockJSONKeyRing reads keys from a JSON array, creates a newKeyRing,
// then tries to unlock them with the provided keyRing using the token in the structure.
// If the token is not available it will fall back to just reading the keys, and leave them locked.
func (keyRing *KeyRing) UnlockJSONKeyRing(jsonData []byte) (newKeyRing *KeyRing, err error) {
	keyObjs, err := unmarshalJSON(jsonData)
	newKeyRing = &KeyRing{}
	err = newKeyRing.newKeyRingFromPGPKeyObject(keyObjs)
	if err != nil {
		return nil, err
	}

	for _, ko := range keyObjs {
		if ko.Token == nil || ko.Signature == nil {
			continue
		}

		message, err := NewPGPMessageFromArmored(*ko.Token)
		if err != nil {
			return nil, err
		}

		signature, err := NewPGPSignatureFromArmored(*ko.Signature)
		if err != nil {
			return nil, err
		}

		token, err := keyRing.Decrypt(message, nil, 0)
		if err != nil {
			return nil, err
		}

		token, err = keyRing.Verify(token, signature, 0)
		if err != nil {
			return nil, err
		}

		if !token.IsVerified() {
			return nil, errors.New("gopenpgp: unable to verify token")
		}

		err = newKeyRing.Unlock(token.GetBinary())
		if err != nil {
			return nil, errors.New("gopenpgp: wrong token")
		}
	}

	return newKeyRing, nil
}

// newKeyRingFromPGPKeyObject fills a KeyRing given an array of pgpKeyObject
func (keyRing *KeyRing) newKeyRingFromPGPKeyObject(keyObjs []pgpKeyObject) (error) {
	keyRing.entities = nil
	for i, ko := range keyObjs {
		if i == 0 {
			keyRing.FirstKeyID = ko.ID
		}
		err := keyRing.readFrom(ko.PrivateKeyReader(), true)
		if err != nil {
			return err
		}
	}
	return nil
}

// unmarshalJSON implements encoding/json.Unmarshaler.
func unmarshalJSON(jsonData []byte) ([]pgpKeyObject, error) {
	keyObjs := []pgpKeyObject{}
	if err := json.Unmarshal(jsonData, &keyObjs); err != nil {
		return nil, err
	}

	if len(keyObjs) == 0 {
		return nil, errors.New("gopenpgp: no key found")
	}

	return keyObjs, nil
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
	err = keyRing.readFrom(r, true)
	return
}

// ReadKeyRing reads an binary data into keyring.
func ReadKeyRing(r io.Reader) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	err = keyRing.readFrom(r, false)
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
