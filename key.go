package pm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

//EncryptedSplit when encrypt attachemt
type EncryptedSplit struct {
	DataPacket []byte
	KeyPacket  []byte
	Algo       string
}

//SessionSplit splited session
type SessionSplit struct {
	Session []byte
	Algo    string
}

//EncryptedSigned encrypt_sign_package
type EncryptedSigned struct {
	Encrypted string
	Signature string
}

const (
	ok         = 0
	notSigned  = 1
	noVerifier = 2
	failed     = 3
)

//DecryptSignedVerify decrypt_sign_verify
type DecryptSignedVerify struct {
	//clear text
	Plaintext string
	//bitmask verify status : 0
	Verify int
	//error message if verify failed
	Message string
}

//CheckPassphrase check is private key passphrase ok
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

//IsKeyExpiredBin ...
func (o *OpenPGP) IsKeyExpiredBin(publicKey []byte) (bool, error) {
	now := o.getNow()
	pubKeyReader := bytes.NewReader(publicKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return true, err
	}
	candidateSubkey := -1
	for _, e := range pubKeyEntries {
		var maxTime time.Time
		for i, subkey := range e.Subkeys {
			if subkey.Sig.FlagsValid &&
				subkey.Sig.FlagEncryptCommunications &&
				subkey.PublicKey.PubKeyAlgo.CanEncrypt() &&
				!subkey.Sig.KeyExpired(now) &&
				(maxTime.IsZero() || subkey.Sig.CreationTime.After(maxTime)) {
				candidateSubkey = i
				maxTime = subkey.Sig.CreationTime
			}
		}

		if candidateSubkey != -1 {
			return false, nil
		}

		// If we don't have any candidate subkeys for encryption and
		// the primary key doesn't have any usage metadata then we
		// assume that the primary key is ok. Or, if the primary key is
		// marked as ok to encrypt to, then we can obviously use it.
		var firstIdentity *openpgp.Identity
		for _, ident := range e.Identities {
			if firstIdentity == nil {
				firstIdentity = ident
			}
			if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
				firstIdentity = ident
				break
			}
		}
		if firstIdentity != nil {
			i := firstIdentity
			if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagEncryptCommunications &&
				e.PrimaryKey.PubKeyAlgo.CanEncrypt() &&
				!i.SelfSignature.KeyExpired(now) {
				return false, nil
			}
		}
	}
	return true, errors.New("keys expired")
}

//IsKeyExpired ....
// will user the cached time to check
func (o *OpenPGP) IsKeyExpired(publicKey string) (bool, error) {
	rawPubKey, err := UnArmor(publicKey)
	if err != nil {
		return false, err
	}
	return o.IsKeyExpiredBin(rawPubKey)
}

// GenerateKey ...
// disabled now, will enable later
// #generat new key with email address. Fix the UserID issue in protonmail system. on Feb 28, 17
// #static generate_key_with_email(email : string, passphrase : string, bits : i32) : open_pgp_key;
// # generate new key
// #static generate_new_key(user_id : string, email : string, passphrase : string, bits : i32) : open_pgp_key;
func (o *OpenPGP) GenerateKey(userName string, domain string, passphrase string, keyType string, bits int) (string, error) {

	if len(userName) <= 0 {
		return "", errors.New("Invalid user name format")
	}
	if len(domain) <= 0 {
		return "", errors.New("Invalid domain")
	}
	email := userName + "@" + domain
	comments := ""
	timeNow := func() time.Time {
		return o.getNow()
	}

	cfg := &packet.Config{RSABits: bits, Time: timeNow}
	newEntity, err := openpgp.NewEntity(email, comments, email, cfg)
	if err != nil {
		return "", err
	}

	if err := newEntity.SelfSign(nil); err != nil {
		return "", err
	}

	rawPwd := []byte(passphrase)
	if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
		if err := newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
			return "", err
		}
	}

	for _, sub := range newEntity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
			if err := sub.PrivateKey.Encrypt(rawPwd); err != nil {
				return "", err
			}
		}
	}

	w := bytes.NewBuffer(nil)
	if err := newEntity.SerializePrivateNoSign(w, nil); err != nil {
		return "", err
	}
	serialized := w.Bytes()
	return ArmorWithType(serialized, pgpPrivateBlockType)
}

// UpdatePrivateKeyPassphrase ...
func (o *OpenPGP) UpdatePrivateKeyPassphrase(privateKey string, oldPassphrase string, newPassphrase string) (string, error) {

	privKey := strings.NewReader(privateKey)
	privKeyEntries, err := openpgp.ReadArmoredKeyRing(privKey)
	if err != nil {
		return "", err
	}

	oldrawPwd := []byte(oldPassphrase)
	newRawPwd := []byte(newPassphrase)
	w := bytes.NewBuffer(nil)
	for _, e := range privKeyEntries {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt(oldrawPwd); err != nil {
				return "", err
			}
		}
		if e.PrivateKey != nil && !e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Encrypt(newRawPwd); err != nil {
				return "", err
			}
		}

		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Decrypt(oldrawPwd); err != nil {
					return "", err
				}
			}
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Encrypt(newRawPwd); err != nil {
					return "", err
				}
			}
		}
		if err := e.SerializePrivateNoSign(w, nil); err != nil {
			return "", err
		}
	}

	serialized := w.Bytes()
	return ArmorWithType(serialized, pgpPrivateBlockType)
}

// PublicKey get a public key from a private key
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

	outString, err := ArmorWithType(outBuf.Bytes(), pgpPublicBlockType)
	if err != nil {
		return "", nil
	}

	return outString, nil
}

// PublicKeyBinOut get a public key from a private key
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

// CheckKey print out the key and subkey fingerprint
func CheckKey(pubKey string) (string, error) {
	pubKeyReader := strings.NewReader(pubKey)
	entries, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return "", err
	}

	for _, e := range entries {
		for _, subKey := range e.Subkeys {
			if !subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications {

				println("SubKey:" + hex.EncodeToString(subKey.PublicKey.Fingerprint[:]))

			}
		}
		println("PrimaryKey:" + hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))

	}
	return "", nil
}
