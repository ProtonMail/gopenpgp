package crypto

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"regexp"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	pgpErrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/internal"
)

// IsMessageEncrypted check if data if has armored PGP message format.
func (pgp *GopenPGP) IsMessageEncrypted(data string) bool {
	re := regexp.MustCompile("^-----BEGIN " + constants.PGPMessageHeader + "-----(?s:.+)-----END " +
		constants.PGPMessageHeader + "-----");
	return re.MatchString(data);
}

// EncryptMessage encrypts a plain text to pgp message with a password
// plainText string: clear text
// output string: armored pgp message
func (sk *SymmetricKey) EncryptMessage(plainText string) (string, error) {
	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, constants.PGPMessageHeader, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}

	config := &packet.Config{
		Time: pgp.getTimeGenerator(),
		DefaultCipher: sk.GetCipherFunc(),
	}

	plaintext, err := openpgp.SymmetricallyEncrypt(w, sk.Key, nil, config)
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

// DecryptMessage decrypts password protected pgp messages
// encrypted string : armored pgp message
// output string : clear text
func (sk *SymmetricKey) DecryptMessage(encrypted string) (string, error) {
	encryptedIO, err := internal.Unarmor(encrypted)
	if err != nil {
		return "", err
	}

	firstTimeCalled := true
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return []byte(sk.Key), nil
		}
		return nil, errors.New("password incorrect")
	}

	config := &packet.Config{
		Time: pgp.getTimeGenerator(),
		DefaultCipher: sk.GetCipherFunc(),
	}
	md, err := openpgp.ReadMessage(encryptedIO.Body, nil, prompt, config)
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

// EncryptMessage encrypts message with unarmored public key, if pass private key and passphrase will also sign
// the message
// plainText : the input
// privateKey : optional required when you want to sign
// passphrase : optional required when you pass the private key and this passphrase should decrypt the private key
// trim : bool true if need to trim new lines
func (publicKey *KeyRing) EncryptMessage(plainText string, privateKey *KeyRing, trimNewlines bool) (string, error) {
	if trimNewlines {
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

	ew, err := EncryptCore(w, publicKey.entities, signEntity, "", false, pgp.getTimeGenerator())
	if err != nil {
		return "", err
	}

	_, err = ew.Write([]byte(plainText))
	ew.Close()
	w.Close()
	return outBuf.String(), err
}

// DecryptMessage decrypts encrypted string using pgp keys
// encryptedText : string armored encrypted
// verifyKey     : Public key for signature verification (optional)
// verifyTime    : Time at verification (necessary only if verifyKey is not nil)
func (privateKey *KeyRing) DecryptMessage(
	encryptedText string, verifyKey *KeyRing, verifyTime int64,
) (plainText string, verified int, err error) {
	privKeyEntries := privateKey.GetEntities()
	var additionalEntries openpgp.EntityList

	if verifyKey != nil {
		additionalEntries = verifyKey.GetEntities()
	}

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	encryptedIO, err := internal.Unarmor(encryptedText)
	if err != nil {
		return "", 0, err
	}

	config := &packet.Config{Time: pgp.getTimeGenerator()}

	messageDetails, err := openpgp.ReadMessage(encryptedIO.Body, privKeyEntries, nil, config)
	if err != nil {
		return "", 0, err
	}

	if verifyKey != nil {
		processSignatureExpiration(messageDetails, verifyTime)
	}

	decrypted := messageDetails.UnverifiedBody
	body, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return "", 0, err
	}
	messageBody := string(body)

	if verifyKey != nil {
		verifyStatus, verifyError := verifyDetailsSignature(messageDetails, verifyKey)

		if verifyStatus == constants.SIGNATURE_FAILED {
			return "", verifyStatus, errors.New(verifyError)
		}

		return messageBody, verifyStatus, nil
	}

	return messageBody, constants.SIGNATURE_NOT_SIGNED, nil
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

func verifyDetailsSignature(md *openpgp.MessageDetails, verifierKey *KeyRing) (int, string) {
	if md.IsSigned {
		if md.SignedBy != nil {
			if len(verifierKey.entities) > 0 {
				matches := verifierKey.entities.KeysById(md.SignedByKeyId)
				if len(matches) > 0 {
					if md.SignatureError == nil {
						return constants.SIGNATURE_OK, ""
					} else {
						return constants.SIGNATURE_FAILED, md.SignatureError.Error()
					}
				}
			} else {
				return constants.SIGNATURE_NO_VERIFIER, ""
			}
		} else {
			return constants.SIGNATURE_NO_VERIFIER, ""
		}
	}

	return constants.SIGNATURE_NOT_SIGNED, ""
}
