package crypto

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	pgpErrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"

	armorUtils "github.com/ProtonMail/go-pm-crypto/armor"
	"github.com/ProtonMail/go-pm-crypto/constants"
	"github.com/ProtonMail/go-pm-crypto/internal"
	"github.com/ProtonMail/go-pm-crypto/models"
)

// DecryptMessageStringKey decrypt encrypted message use private key (string )
// encryptedText : string armored encrypted
// privateKey : armored private use to decrypt message
// passphrase : match with private key to decrypt message
// Use: ios/android only
func (pm *PmCrypto) DecryptMessageStringKey(encryptedText string, privateKey string, passphrase string) (string, error) {
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
// privateKey : keyring with private key to decrypt message, could be mutiple keys
// passphrase : match with private key to decrypt message
// Use ios/android only
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

	println(4)
	return string(b), nil
}

func decryptCore(encryptedText string, additionalEntries openpgp.EntityList, privKey *KeyRing, passphrase string, timeFunc func() time.Time) (*openpgp.MessageDetails, error) {
	rawPwd := []byte(passphrase)
	privKey.Unlock(rawPwd)

	privKeyEntries := privKey.entities
	for _, entity := range privKey.entities {
		privKeyEntries = append(privKeyEntries, entity)
	}

	if additionalEntries != nil {
		for _, e := range additionalEntries {
			privKeyEntries = append(privKeyEntries, e)
		}
	}

	encryptedio, err := internal.Unarmor(encryptedText)
	if err != nil {
		return nil, err
	}

	config := &packet.Config{Time: timeFunc}

	md, err := openpgp.ReadMessage(encryptedio.Body, privKeyEntries, nil, config)
	return md, err
}

// Use: ios/android only
func (pm *PmCrypto) DecryptMessageVerify(encryptedText string, verifierKey *KeyRing, privateKeyRing *KeyRing, passphrase string, verifyTime int64) (*models.DecryptSignedVerify, error) {
	// DecryptMessageVerifyBinKeyPrivBinKeys decrypt message and verify the signature
	// verifierKey []byte: unarmored verifier keys
	// privateKey []byte: unarmored private key to decrypt. could be mutiple

	out := &models.DecryptSignedVerify{}
	out.Verify = failed

	var verifierEntries openpgp.EntityList
	if len(verifierKey.entities) == 0 {
		out.Verify = noVerifier
	}

	md, err := decryptCore(encryptedText, verifierEntries, privateKeyRing, passphrase, func() time.Time { return time.Unix(0, 0) }) // TODO: I doubt this time is correct

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

// Handle signature time verification manually, so we can add a margin to the creationTime check.
func processSignatureExpiration(md *openpgp.MessageDetails, verifyTime int64) {
	if md.SignatureError == pgpErrors.ErrSignatureExpired {
		if verifyTime > 0 {
			created := md.Signature.CreationTime.Unix()
			expires := int64(math.MaxInt64)
			if md.Signature.KeyLifetimeSecs != nil {
				expires = int64(*md.Signature.KeyLifetimeSecs) + created
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

// Use: ios/android only
//EncryptMessageWithPassword encrypt a plain text to pgp message with a password
//plainText string: clear text
//output string: armored pgp message
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

// Use ios/android only
// EncryptMessageBinKey encrypt message with unarmored public key, if pass private key and passphrase will also sign the message
// publicKey : bytes unarmored public key
// plainText : the input
// privateKey : optional required when you want to sign
// passphrase : optional required when you pass the private key and this passphrase must could decrypt the private key
func (pm *PmCrypto) EncryptMessage(plainText string, publicKey *KeyRing, privateKey *KeyRing, passphrase string, trim bool) (string, error) {

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

		signEntity := privateKey.GetSigningEntity(passphrase)

		if signEntity == nil {
			return "", errors.New("cannot sign message, signer key is not unlocked")
		}
	}

	ew, err := EncryptCore(w, publicKey.entities, signEntity, "", false, pm.getTimeGenerator())

	_, _ = ew.Write([]byte(plainText))
	ew.Close()
	w.Close()
	return outBuf.String(), nil
}

// Use: ios/android only
//DecryptMessageWithPassword decrypt a pgp message with a password
//encrypted string : armored pgp message
//output string : clear text
func (pm *PmCrypto) DecryptMessageWithPassword(encrypted string, password string) (string, error) {
	encryptedio, err := internal.Unarmor(encrypted)
	if err != nil {
		return "", err
	}

	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return []byte(password), nil
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
