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
	Fingerprint string
	PublicKey   string `json:",omitempty"`
	PrivateKey  string
	Primary int
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

// Signature is be used to check a signature. Because the signature is checked
// when the reader is consumed, Signature must only be used after EOF has been
// seen. A signature is only valid if s.Err() returns nil, otherwise the
// sender's identity cannot be trusted.
type Signature struct {
	md *openpgp.MessageDetails
}

// SignedString wraps string with a Signature
type SignedString struct {
	String string
	Signed *Signature
}

// Err returns a non-nil error if the signature is invalid.
func (s *Signature) Err() error {
	return s.md.SignatureError
}

// KeyRing returns the key ring that was used to produce the signature, if
// available.
func (s *Signature) KeyRing() *KeyRing {
	if s.md.SignedBy == nil {
		return nil
	}

	return &KeyRing{
		entities: openpgp.EntityList{s.md.SignedBy.Entity},
	}
}

// IsBy returns true if the signature has been created by kr's owner.
func (s *Signature) IsBy(kr *KeyRing) bool {
	// Use fingerprint if possible
	if s.md.SignedBy != nil {
		for _, e := range kr.entities {
			if e.PrimaryKey.Fingerprint == s.md.SignedBy.PublicKey.Fingerprint {
				return true
			}
		}
		return false
	}

	for _, e := range kr.entities {
		if e.PrimaryKey.KeyId == s.md.SignedByKeyId {
			return true
		}
	}
	return false
}

// GetEntities returns openpgp entities contained in this KeyRing.
func (kr *KeyRing) GetEntities() openpgp.EntityList {
	return kr.entities
}

// GetSigningEntity returns first private unlocked signing entity from keyring.
func (kr *KeyRing) GetSigningEntity() (*openpgp.Entity, error) {
	var signEntity *openpgp.Entity

	for _, e := range kr.entities {
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
func (kr *KeyRing) Unlock(passphrase []byte) error {
	// Build a list of keys to decrypt
	var keys []*packet.PrivateKey
	for _, e := range kr.entities {
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
func (kr *KeyRing) UnlockWithPassphrase(passphrase string) error {
	return kr.Unlock([]byte(passphrase))
}

// WriteArmoredPublicKey outputs armored public keys from the keyring to w.
func (kr *KeyRing) WriteArmoredPublicKey(w io.Writer) (err error) {
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}

	for _, e := range kr.entities {
		if err = e.Serialize(aw); err != nil {
			aw.Close()
			return
		}
	}

	err = aw.Close()
	return
}

// GetArmoredPublicKey returns the armored public keys from this keyring.
func (kr *KeyRing) GetArmoredPublicKey() (s string, err error) {
	b := &bytes.Buffer{}
	if err = kr.WriteArmoredPublicKey(b); err != nil {
		return
	}

	s = b.String()
	return
}

// WritePublicKey outputs unarmored public keys from the keyring to w.
func (kr *KeyRing) WritePublicKey(w io.Writer) (err error) {
	for _, e := range kr.entities {
		if err = e.Serialize(w); err != nil {
			return
		}
	}

	return
}

// GetPublicKey returns the unarmored public keys from this keyring.
func (kr *KeyRing) GetPublicKey() (b []byte, err error) {
	var outBuf bytes.Buffer
	if err = kr.WritePublicKey(&outBuf); err != nil {
		return
	}

	b = outBuf.Bytes()
	return
}

// GetFingerprint gets the fingerprint from the keyring.
func (kr *KeyRing) GetFingerprint() (string, error) {
	for _, entity := range kr.entities {
		fp := entity.PrimaryKey.Fingerprint
		return hex.EncodeToString(fp[:]), nil
	}
	return "", errors.New("can't find public key")
}

// CheckPassphrase checks if private key passphrase is correct for every sub key.
func (kr *KeyRing) CheckPassphrase(passphrase string) bool {
	var keys []*packet.PrivateKey

	for _, entity := range kr.entities {
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
func (kr *KeyRing) readFrom(r io.Reader, armored bool) error {
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

	kr.entities = append(kr.entities, entities...)
	return nil
}

// BuildKeyRing reads keyring from binary data
func (pgp *GopenPGP) BuildKeyRing(binKeys []byte) (kr *KeyRing, err error) {
	kr = &KeyRing{}
	entriesReader := bytes.NewReader(binKeys)
	err = kr.readFrom(entriesReader, false)

	return
}

// BuildKeyRingNoError does not return error on fail
func (pgp *GopenPGP) BuildKeyRingNoError(binKeys []byte) (kr *KeyRing) {
	kr, _ = pgp.BuildKeyRing(binKeys)
	return
}

// BuildKeyRingArmored reads armored string and returns keyring
func (pgp *GopenPGP) BuildKeyRingArmored(key string) (kr *KeyRing, err error) {
	keyRaw, err := armorUtils.Unarmor(key)
	if err != nil {
		return nil, err
	}
	keyReader := bytes.NewReader(keyRaw)
	keyEntries, err := openpgp.ReadKeyRing(keyReader)
	return &KeyRing{entities: keyEntries}, err
}

// UnmarshalJSON implements encoding/json.Unmarshaler.
func (kr *KeyRing) UnmarshalJSON(b []byte) (err error) {
	kr.entities = nil

	keyObjs := []pgpKeyObject{}
	if err = json.Unmarshal(b, &keyObjs); err != nil {
		return
	}

	if len(keyObjs) == 0 {
		return
	}

	for i, ko := range keyObjs {
		if i == 0 {
			kr.FirstKeyID = ko.ID
		}
		err = kr.readFrom(ko.PrivateKeyReader(), true)
		if err != nil {
			return err
		}
	}

	return nil
}

// Identities returns the list of identities associated with this key ring.
func (kr *KeyRing) Identities() []*Identity {
	var identities []*Identity
	for _, e := range kr.entities {
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
func (kr *KeyRing) KeyIds() []uint64 {
	var res []uint64
	for _, e := range kr.entities {
		res = append(res, e.PrimaryKey.KeyId)
	}
	return res
}

// ReadArmoredKeyRing reads an armored data into keyring.
func ReadArmoredKeyRing(r io.Reader) (kr *KeyRing, err error) {
	kr = &KeyRing{}
	err = kr.readFrom(r, true)
	return
}

// ReadKeyRing reads an binary data into keyring.
func ReadKeyRing(r io.Reader) (kr *KeyRing, err error) {
	kr = &KeyRing{}
	err = kr.readFrom(r, false)
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
		return filteredKeys, errors.New("all contacts keys are expired")
	}

	return filteredKeys, nil
}
