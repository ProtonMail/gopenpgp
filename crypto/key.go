package crypto

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"time"

	"github.com/ProtonMail/go-pm-crypto/armor"
	"github.com/ProtonMail/go-pm-crypto/constants"
	"github.com/ProtonMail/go-pm-crypto/models"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// SymmetricKey stores a decrypted session key.
type SymmetricKey struct {
	// The clear base64-encoded key.
	Key []byte
	// The algorithm used by this key.
	Algo string
}

// SymmetricallyEncryptedTag is 18 with the 2 highest order bits set to 1
const SymmetricallyEncryptedTag = 210

var symKeyAlgos = map[string]packet.CipherFunction{
	"3des":      packet.Cipher3DES,
	"tripledes": packet.Cipher3DES,
	"cast5":     packet.CipherCAST5,
	"aes128":    packet.CipherAES128,
	"aes192":    packet.CipherAES192,
	"aes256":    packet.CipherAES256,
}

// GetCipherFunc returns function corresponding to an algorithm used in this SymmetricKey
func (sk *SymmetricKey) GetCipherFunc() packet.CipherFunction {
	cf, ok := symKeyAlgos[sk.Algo]
	if ok {
		return cf
	}

	panic("pm-crypto: unsupported cipher function: " + sk.Algo)
}

// GetBase64Key returns a key as base64 encoded string
func (sk *SymmetricKey) GetBase64Key() string {
	return base64.StdEncoding.EncodeToString(sk.Key)
}

func newSymmetricKey(ek *packet.EncryptedKey) *SymmetricKey {
	var algo string
	for k, v := range symKeyAlgos {
		if v == ek.CipherFunc {
			algo = k
			break
		}
	}
	if algo == "" {
		panic(fmt.Sprintf("pm-crypto: unsupported cipher function: %v", ek.CipherFunc))
	}

	return &SymmetricKey{
		Key:  ek.Key, //base64.StdEncoding.EncodeToString(ek.Key),
		Algo: algo,
	}
}

// DecryptAttKey and returns a symmetric key
func DecryptAttKey(kr *KeyRing, keyPacket string) (key *SymmetricKey, err error) {
	r := base64.NewDecoder(base64.StdEncoding, strings.NewReader(keyPacket))
	packets := packet.NewReader(r)

	var p packet.Packet
	if p, err = packets.Next(); err != nil {
		return
	}

	ek := p.(*packet.EncryptedKey)

	var decryptErr error
	for _, key := range kr.entities.DecryptionKeys() {
		priv := key.PrivateKey
		if priv.Encrypted {
			continue
		}

		if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
			break
		}
	}

	if decryptErr != nil {
		err = fmt.Errorf("pm-crypto: cannot decrypt encrypted key packet: %v", decryptErr)
		return
	}

	key = newSymmetricKey(ek)
	return
}

// SeparateKeyAndData from packets in a pgp session
func SeparateKeyAndData(kr *KeyRing, r io.Reader, estimatedLength int, garbageCollector int) (outSplit *models.EncryptedSplit, err error) {
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	packets := packet.NewReader(r)
	outSplit = &models.EncryptedSplit{}
	gcCounter := 0

	// Save encrypted key and signature apart
	var ek *packet.EncryptedKey
	var decryptErr error
	for {
		var p packet.Packet
		if p, err = packets.Next(); err == io.EOF {
			err = nil
			break
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			// We got an encrypted key. Try to decrypt it with each available key
			if ek != nil && ek.Key != nil {
				break
			}
			ek = p

			if kr != nil {
				for _, key := range kr.entities.DecryptionKeys() {
					priv := key.PrivateKey
					if priv.Encrypted {
						continue
					}

					if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
						break
					}
				}
			}
		case *packet.SymmetricallyEncrypted:
			// The code below is optimized to not
			var b bytes.Buffer
			// 2^16 is an estimation of the size difference between input and output, the size difference is most probably
			// 16 bytes at a maximum though.
			// We need to avoid triggering a grow from the system as this will allocate too much memory causing problems
			// in low-memory environments
			b.Grow(1<<16 + estimatedLength)
			// empty encoded length + start byte
			b.Write(make([]byte, 6))
			b.WriteByte(byte(1))
			actualLength := 1
			block := make([]byte, 128)
			for {
				n, err := p.Contents.Read(block)
				if err == io.EOF {
					break
				}
				b.Write(block[:n])
				actualLength += n
				gcCounter += n
				if gcCounter > garbageCollector && garbageCollector > 0 {
					runtime.GC()
					gcCounter = 0
				}
			}

			// quick encoding
			symEncryptedData := b.Bytes()
			if actualLength < 192 {
				symEncryptedData[4] = byte(210)
				symEncryptedData[5] = byte(actualLength)
				symEncryptedData = symEncryptedData[4:]
			} else if actualLength < 8384 {
				actualLength = actualLength - 192
				symEncryptedData[3] = byte(210)
				symEncryptedData[4] = 192 + byte(actualLength>>8)
				symEncryptedData[5] = byte(actualLength)
				symEncryptedData = symEncryptedData[3:]
			} else {
				symEncryptedData[0] = byte(210)
				symEncryptedData[1] = byte(255)
				symEncryptedData[2] = byte(actualLength >> 24)
				symEncryptedData[3] = byte(actualLength >> 16)
				symEncryptedData[4] = byte(actualLength >> 8)
				symEncryptedData[5] = byte(actualLength)
			}

			outSplit.DataPacket = symEncryptedData
			break

		}
	}
	if decryptErr != nil {
		err = fmt.Errorf("pm-crypto: cannot decrypt encrypted key packet: %v", decryptErr)
		return
	}
	if ek == nil {
		err = errors.New("pm-crypto: packets don't include an encrypted key packet")
		return
	}

	if kr == nil {
		var buf bytes.Buffer
		ek.Serialize(&buf)
		outSplit.KeyPacket = buf.Bytes()
	} else {
		key := newSymmetricKey(ek)
		outSplit.KeyPacket = key.Key
		outSplit.Algo = key.Algo
	}

	return outSplit, nil
}

// SetKey encrypts the provided key.
func SetKey(kr *KeyRing, symKey *SymmetricKey) (packets string, err error) {
	b := &bytes.Buffer{}
	w := base64.NewEncoder(base64.StdEncoding, b)

	cf := symKey.GetCipherFunc()

	if len(kr.entities) == 0 {
		err = fmt.Errorf("pm-crypto: cannot set key: key ring is empty")
		return
	}

	var pub *packet.PublicKey
	for _, e := range kr.entities {
		for _, subKey := range e.Subkeys {
			if !subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications {
				pub = subKey.PublicKey
				break
			}
		}
		if pub == nil && len(e.Identities) > 0 {
			var i *openpgp.Identity
			for _, i = range e.Identities {
				break
			}
			if i.SelfSignature.FlagsValid || i.SelfSignature.FlagEncryptStorage || i.SelfSignature.FlagEncryptCommunications {
				pub = e.PrimaryKey
			}
		}
		if pub != nil {
			break
		}
	}
	if pub == nil {
		err = fmt.Errorf("pm-crypto: cannot set key: no public key available")
		return
	}

	if err = packet.SerializeEncryptedKey(w, pub, cf, symKey.Key, nil); err != nil {
		err = fmt.Errorf("pm-crypto: cannot set key: %v", err)
		return
	}

	if err = w.Close(); err != nil {
		err = fmt.Errorf("pm-crypto: cannot set key: %v", err)
		return
	}

	packets = b.String()
	return
}

// IsKeyExpiredBin checks if the given key is expired. Input in binary format
func (pm *PmCrypto) IsKeyExpiredBin(publicKey []byte) (bool, error) {
	now := pm.getNow()
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
				!subkey.PublicKey.KeyExpired(subkey.Sig, now) &&
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
				!e.PrimaryKey.KeyExpired(i.SelfSignature, now) {
				return false, nil
			}
		}
	}
	return true, errors.New("keys expired")
}

const (
	ok         = 0
	notSigned  = 1
	noVerifier = 2
	failed     = 3
)

// IsKeyExpired checks if the given key is expired. Input in armored format
func (pm *PmCrypto) IsKeyExpired(publicKey string) (bool, error) {
	rawPubKey, err := armor.Unarmor(publicKey)
	if err != nil {
		return false, err
	}
	return pm.IsKeyExpiredBin(rawPubKey)
}

func (pm *PmCrypto) generateKey(userName string, domain string, passphrase string, keyType string, bits int,
	prime1 []byte, prime2 []byte, prime3 []byte, prime4 []byte) (string, error) {

	if len(userName) <= 0 {
		return "", errors.New("invalid user name format")
	}
	var email = userName

	if len(domain) > 0 {
		email = email + "@" + domain
	}

	comments := ""

	cfg := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       bits,
		Time:          pm.getTimeGenerator(),
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
	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// GenerateRSAKeyWithPrimes generates RSA key with given primes.
func (pm *PmCrypto) GenerateRSAKeyWithPrimes(
	userName, domain, passphrase string,
	bits int,
	primeone, primetwo, primethree, primefour []byte,
) (string, error) {
	return pm.generateKey(userName, domain, passphrase, "rsa", bits, primeone, primetwo, primethree, primefour)
}

// GenerateKey and generate primes
func (pm *PmCrypto) GenerateKey(userName string, domain string, passphrase string, keyType string, bits int) (string, error) {
	return pm.generateKey(userName, domain, passphrase, keyType, bits, nil, nil, nil, nil)
}

// UpdatePrivateKeyPassphrase decrypts the given private key with oldPhrase and re-encrypts with the newPassphrase
func (pm *PmCrypto) UpdatePrivateKeyPassphrase(privateKey string, oldPassphrase string, newPassphrase string) (string, error) {
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
	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// CheckKey prints out the key and subkey fingerprint
func (pm *PmCrypto) CheckKey(pubKey string) (string, error) {
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
