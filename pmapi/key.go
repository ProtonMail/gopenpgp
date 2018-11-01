package pmapi

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	//	"net/http"
	//	"net/url"
	"strings"

	//"github.com/ProtonMail/go-pm-crypto/armor"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// A decrypted session key.
type SymmetricKey struct {
	// The clear base64-encoded key.
	Key string
	// The algorithm used by this key.
	Algo string
}

//18 with the 2 highest order bits set to 1
const SymmetricallyEncryptedTag = 210

var symKeyAlgos = map[string]packet.CipherFunction{
	"3des":      packet.Cipher3DES,
	"tripledes": packet.Cipher3DES,
	"cast5":     packet.CipherCAST5,
	"aes128":    packet.CipherAES128,
	"aes192":    packet.CipherAES192,
	"aes256":    packet.CipherAES256,
}

// Get this's cipher function.
func (sk *SymmetricKey) cipherFunc() packet.CipherFunction {
	cf, ok := symKeyAlgos[sk.Algo]
	if ok {
		return cf
	}

	panic("pmapi: unsupported cipher function: " + sk.Algo)
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
		panic(fmt.Sprintf("pmapi: unsupported cipher function: %v", ek.CipherFunc))
	}

	return &SymmetricKey{
		Key:  base64.StdEncoding.EncodeToString(ek.Key),
		Algo: algo,
	}
}

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
		err = fmt.Errorf("pmapi: cannot decrypt encrypted key packet: %v", decryptErr)
		return
	}

	key = newSymmetricKey(ek)
	return
}

func SeparateKeyAndData(kr *KeyRing, r io.Reader) (key *SymmetricKey, symEncryptedData []byte, err error) {
	packets := packet.NewReader(r)

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

			for _, key := range kr.entities.DecryptionKeys() {
				priv := key.PrivateKey
				if priv.Encrypted {
					continue
				}

				if decryptErr = ek.Decrypt(priv, nil); decryptErr == nil {
					break
				}
			}
		case *packet.SymmetricallyEncrypted:
			var packetContents []byte
			if packetContents, err = ioutil.ReadAll(p.Contents); err != nil {
				return
			}

			encodedLength := encodedLength(len(packetContents) + 1)

			symEncryptedData = append(symEncryptedData, byte(210))
			symEncryptedData = append(symEncryptedData, encodedLength...)
			symEncryptedData = append(symEncryptedData, byte(1))
			symEncryptedData = append(symEncryptedData, packetContents...)
			break
		}
	}
	if decryptErr != nil {
		err = fmt.Errorf("pmapi: cannot decrypt encrypted key packet: %v", decryptErr)
		return
	}
	if ek == nil {
		err = errors.New("pmapi: packets don't include an encrypted key packet")
		return
	}
	if ek.Key == nil {
		err = errors.New("pmapi: could not find any key to decrypt key")
		return
	}

	key = newSymmetricKey(ek)
	return
}

//encode length based on 4.2.2. in the RFC
func encodedLength(length int) (b []byte) {
	if length < 192 {
		b = append(b, byte(length))
	} else if length < 8384 {
		length = length - 192
		b = append(b, 192+byte(length>>8))
		b = append(b, byte(length))
	} else {
		b = append(b, byte(255))
		b = append(b, byte(length>>24))
		b = append(b, byte(length>>16))
		b = append(b, byte(length>>8))
		b = append(b, byte(length))
	}
	return
}

// SetKey encrypts the provided key.
func SetKey(kr *KeyRing, symKey *SymmetricKey) (packets string, err error) {
	b := &bytes.Buffer{}
	w := base64.NewEncoder(base64.StdEncoding, b)

	cf := symKey.cipherFunc()

	k, err := base64.StdEncoding.DecodeString(symKey.Key)
	if err != nil {
		err = fmt.Errorf("pmapi: cannot set key: %v", err)
		return
	}

	if len(kr.entities) == 0 {
		err = fmt.Errorf("pmapi: cannot set key: key ring is empty")
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
		err = fmt.Errorf("pmapi: cannot set key: no public key available")
		return
	}

	if err = packet.SerializeEncryptedKey(w, pub, cf, k, nil); err != nil {
		err = fmt.Errorf("pmapi: cannot set key: %v", err)
		return
	}

	if err = w.Close(); err != nil {
		err = fmt.Errorf("pmapi: cannot set key: %v", err)
		return
	}

	packets = b.String()
	return
}
