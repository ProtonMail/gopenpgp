package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	pgpErrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"

	armorUtils "github.com/ProtonMail/gopenpgp/armor"
	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/internal"
	"github.com/ProtonMail/gopenpgp/models"
)

// DecryptMessageStringKey decrypts encrypted message use private key (string)
// encryptedText : string armored encrypted
// privateKey : armored private use to decrypt message
// passphrase : match with private key to decrypt message
func (pm *PmCrypto) DecryptMessageStringKey(
	encryptedText, privateKey, passphrase string,
) (string, error) {
	privKeyRaw, err := armorUtils.Unarmor(privateKey)
	if err != nil {
		return "", err
	}
	privKeyReader := bytes.NewReader(privKeyRaw)
	privKeyEntries, err := openpgp.ReadKeyRing(privKeyReader)
	if err != nil {
		return "", err
	}

	return pm.DecryptMessage(encryptedText, &KeyRing{entities: privKeyEntries}, passphrase)
}

// DecryptMessage decrypts encrypted string using keyring
// encryptedText : string armored encrypted
// privateKey : keyring with private key to decrypt message, could be multiple keys
// passphrase : match with private key to decrypt message
func (pm *PmCrypto) DecryptMessage(encryptedText string, privateKey *KeyRing, passphrase string) (string, error) {
	md, err := decryptCore(encryptedText, nil, privateKey, passphrase, pm.getTimeGenerator())
	if err != nil {
		return "", err
	}

	decrypted := md.UnverifiedBody
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func decryptCore(
	encryptedText string, additionalEntries openpgp.EntityList,
	privKey *KeyRing, passphrase string,
	timeFunc func() time.Time,
) (*openpgp.MessageDetails, error) {
	rawPwd := []byte(passphrase)
	if err := privKey.Unlock(rawPwd); err != nil {
		err = fmt.Errorf("pm-crypto: cannot decrypt passphrase: %v", err)
		return nil, err
	}

	privKeyEntries := privKey.entities

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	encryptedio, err := internal.Unarmor(encryptedText)
	if err != nil {
		return nil, err
	}

	config := &packet.Config{Time: timeFunc}

	md, err := openpgp.ReadMessage(encryptedio.Body, privKeyEntries, nil, config)
	return md, err
}

// DecryptMessageVerify decrypts message and verify the signature
// encryptedText:  string armored encrypted
// verifierKey    []byte: unarmored verifier keys
// privateKeyRing []byte: unarmored private key to decrypt. could be multiple
// passphrase:    match with private key to decrypt message
func (pm *PmCrypto) DecryptMessageVerify(
	encryptedText string, verifierKey, privateKeyRing *KeyRing,
	passphrase string, verifyTime int64,
) (*models.DecryptSignedVerify, error) {
	out := &models.DecryptSignedVerify{}
	out.Verify = failed

	var verifierEntries openpgp.EntityList
	if len(verifierKey.entities) == 0 {
		out.Verify = noVerifier
	}

	md, err := decryptCore(
		encryptedText,
		verifierEntries,
		privateKeyRing,
		passphrase,
		func() time.Time { return time.Unix(0, 0) }) // TODO: I doubt this time is correct

	if err != nil {
		return nil, err
	}

	decrypted := md.UnverifiedBody
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return nil, err
	}

	processSignatureExpiration(md, verifyTime)

	out.Plaintext = string(b)
	if md.IsSigned {
		if md.SignedBy != nil {
			if len(verifierKey.entities) > 0 {
				matches := verifierKey.entities.KeysById(md.SignedByKeyId)
				if len(matches) > 0 {
					if md.SignatureError == nil {
						out.Verify = ok
					} else {
						out.Message = md.SignatureError.Error()
						out.Verify = failed
					}
				}
			} else {
				out.Verify = noVerifier
			}
		} else {
			out.Verify = noVerifier
		}
	} else {
		out.Verify = notSigned
	}
	return out, nil
}

// processSignatureExpiration handles signature time verification manually, so we can add a margin to the
// creationTime check.
func processSignatureExpiration(md *openpgp.MessageDetails, verifyTime int64) {
	if md.SignatureError == pgpErrors.ErrSignatureExpired {
		if verifyTime > 0 {
			created := md.Signature.CreationTime.Unix()
			expires := int64(math.MaxInt64)
			if md.Signature.SigLifetimeSecs != nil {
				expires = int64(*md.Signature.SigLifetimeSecs) + created
			}
			if created-internal.CreationTimeOffset <= verifyTime && verifyTime <= expires {
				md.SignatureError = nil
			}
		} else {
			// verifyTime = 0: time check disabled, everything is okay
			md.SignatureError = nil
		}
	}
}

// EncryptMessageWithPassword encrypts a plain text to pgp message with a password
// plainText string: clear text
// output string: armored pgp message
func (pm *PmCrypto) EncryptMessageWithPassword(plainText string, password string) (string, error) {
	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, constants.PGPMessageHeader, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}

	config := &packet.Config{Time: pm.getTimeGenerator()}
	plaintext, err := openpgp.SymmetricallyEncrypt(w, []byte(password), nil, config)
	if err != nil {
		return "", err
	}
	message := []byte(plainText)
	_, err = plaintext.Write(message)
	if err != nil {
		return "", err
	}
	err = plaintext.Close()
	if err != nil {
		return "", err
	}
	w.Close()

	return outBuf.String(), nil
}

// EncryptMessage encrypts message with unarmored public key, if pass private key and passphrase will also sign
// the message
// publicKey : bytes unarmored public key
// plainText : the input
// privateKey : optional required when you want to sign
// passphrase : optional required when you pass the private key and this passphrase should decrypt the private key
// trim : bool true if need to trim new lines
func (pm *PmCrypto) EncryptMessage(
	plainText string, publicKey, privateKey *KeyRing,
	passphrase string, trim bool,
) (string, error) {
	if trim {
		plainText = internal.TrimNewlines(plainText)
	}
	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, constants.PGPMessageHeader, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}

	var signEntity *openpgp.Entity

	if len(passphrase) > 0 && len(privateKey.entities) > 0 {
		var err error
		signEntity, err = privateKey.GetSigningEntity(passphrase)
		if err != nil {
			return "", err
		}
	}

	ew, err := EncryptCore(w, publicKey.entities, signEntity, "", false, pm.getTimeGenerator())
	if err != nil {
		return "", err
	}

	_, err = ew.Write([]byte(plainText))
	ew.Close()
	w.Close()
	return outBuf.String(), err
}

// DecryptMessageWithPassword decrypts a pgp message with a password
// encrypted string : armored pgp message
// output string : clear text
func (pm *PmCrypto) DecryptMessageWithPassword(encrypted string, password string) (string, error) {
	encryptedio, err := internal.Unarmor(encrypted)
	if err != nil {
		return "", err
	}

	firstTimeCalled := true
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return []byte(password), nil
		}
		return nil, errors.New("password incorrect")
	}

	config := &packet.Config{Time: pm.getTimeGenerator()}
	md, err := openpgp.ReadMessage(encryptedio.Body, nil, prompt, config)
	if err != nil {
		return "", err
	}

	messageBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(messageBuf, md.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return messageBuf.String(), nil
}
