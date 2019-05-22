package crypto

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"time"

	"golang.org/x/crypto/openpgp"
	pgpErrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/internal"
)

// Encrypt encrypts a PlainMessage, outputs a PGPMessage.
// If an unlocked private key is also provided it will also sign the message.
// plainText : the input
// privateKey : (optional) to include signature in the message
func (keyRing *KeyRing) Encrypt(message *PlainMessage, privateKey *KeyRing) (*PGPMessage, error) {
	encrypted, err := asymmetricEncrypt(message.GetBinary(), keyRing, privateKey, true)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// Decrypt decrypts encrypted string using pgp keys, returning a PlainMessage
// message    : PGPMessage
// verifyKey  : Public key for signature verification (optional)
// verifyTime : Time at verification (necessary only if verifyKey is not nil)
func (keyRing *KeyRing) Decrypt(message *PGPMessage, verifyKey *KeyRing, verifyTime int64) (*PlainMessage, error) {
	decrypted, verifyStatus, err := asymmetricDecrypt(message.NewReader(), keyRing, verifyKey, verifyTime)
	if err != nil {
		return nil, err
	}

	binMessage := NewPlainMessage(decrypted)
	binMessage.Verified = verifyStatus
	return binMessage, nil
}

// Sign generates and attaches a PGPSignature to a given PlainMessage
func (keyRing *KeyRing) SignDetached(message *PlainMessage) (*PlainMessage, *PGPSignature, error) {
	signEntity, err := keyRing.GetSigningEntity()
	if err != nil {
		return nil, nil, err
	}

	config := &packet.Config{DefaultHash:crypto.SHA512 , Time: pgp.getTimeGenerator()}
	var outBuf bytes.Buffer
	//sign bin
	if err := openpgp.DetachSign(&outBuf, signEntity, message.NewReader(), config); err != nil {
		return nil, nil, err
	}

	return message, NewPGPSignature(outBuf.Bytes()), nil
}

// Verify verifies a PlainMessage with embedded a PGPSignature
// and returns a PlainMessage with the filled Verified field.
func (keyRing *KeyRing) VerifyDetached(
	message *PlainMessage, signature *PGPSignature, verifyTime int64,
) (*PlainMessage, error) {
	var err error
	message.Verified, err = verifySignature(
		keyRing.GetEntities(),
		message.NewReader(),
		signature.GetBinary(),
		verifyTime,
	)
	return message, err
}

// ------ INTERNAL FUNCTIONS -------

// Core for encryption+signature functions
func asymmetricEncrypt (data []byte, publicKey *KeyRing, privateKey *KeyRing, isBinary bool) ([]byte, error) {
	var outBuf bytes.Buffer
	var encryptWriter io.WriteCloser
	var signEntity *openpgp.Entity
	var err error

	if privateKey != nil && len(privateKey.entities) > 0 {
		var err error
		signEntity, err = privateKey.GetSigningEntity()
		if err != nil {
			return nil, err
		}
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pgp.getTimeGenerator()}

	hints := &openpgp.FileHints{
		IsBinary: isBinary,
		FileName: "",
	}

	if isBinary {
		encryptWriter, err = openpgp.Encrypt(&outBuf, publicKey.entities, signEntity, hints, config)
	} else {
		encryptWriter, err = openpgp.EncryptText(&outBuf, publicKey.entities, signEntity, hints, config)
	}
	if err != nil {
		return nil, err
	}

	_, err = encryptWriter.Write(data)
	encryptWriter.Close()

	if err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}


// Core for decryption+verification functions
func asymmetricDecrypt (
	encryptedIO io.Reader, privateKey *KeyRing, verifyKey *KeyRing, verifyTime int64,
) (plainText []byte, verified int, err error) {
	privKeyEntries := privateKey.GetEntities()
	var additionalEntries openpgp.EntityList

	if verifyKey != nil {
		additionalEntries = verifyKey.GetEntities()
	}

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	config := &packet.Config{Time: pgp.getTimeGenerator()}

	messageDetails, err := openpgp.ReadMessage(encryptedIO, privKeyEntries, nil, config)
	if err != nil {
		return nil, constants.SIGNATURE_NOT_SIGNED, err
	}

	if verifyKey != nil {
		processSignatureExpiration(messageDetails, verifyTime)
	}

	body, err := ioutil.ReadAll(messageDetails.UnverifiedBody)
	if err != nil {
		return nil, constants.SIGNATURE_NOT_SIGNED, err
	}

	if verifyKey != nil {
		verifyStatus, verifyError := verifyDetailsSignature(messageDetails, verifyKey)

		if verifyStatus == constants.SIGNATURE_FAILED {
			return nil, verifyStatus, errors.New(verifyError)
		}

		return body, verifyStatus, nil
	}

	return body, constants.SIGNATURE_NOT_SIGNED, nil
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

// Verify signature from message details
func verifyDetailsSignature(md *openpgp.MessageDetails, verifierKey *KeyRing) (int, string) {
	if md.IsSigned {
		if md.SignedBy != nil {
			if len(verifierKey.entities) > 0 {
				matches := verifierKey.entities.KeysById(md.SignedByKeyId)
				if len(matches) > 0 {
					if md.SignatureError == nil {
						return constants.SIGNATURE_OK, ""
					}
					return constants.SIGNATURE_FAILED, md.SignatureError.Error()
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


// verifySignature verifies if a signature is valid with the entity list
func verifySignature(
	pubKeyEntries openpgp.EntityList, origText io.Reader, signature []byte, verifyTime int64) (int, error) {
	config := &packet.Config{}
	if verifyTime == 0 {
		config.Time = func() time.Time {
			return time.Unix(0, 0)
		}
	} else {
		config.Time = func() time.Time {
			return time.Unix(verifyTime+internal.CreationTimeOffset, 0)
		}
	}
	signatureReader := bytes.NewReader(signature)

	signer, err := openpgp.CheckDetachedSignature(pubKeyEntries, origText, signatureReader, config)

	if err == pgpErrors.ErrSignatureExpired && signer != nil {
		if verifyTime > 0 { // if verifyTime = 0: time check disabled, everything is okay
			// Maybe the creation time offset pushed it over the edge
			// Retry with the actual verification time
			config.Time = func() time.Time {
				return time.Unix(verifyTime, 0)
			}

			_, err = signatureReader.Seek(0, io.SeekStart)
			if err != nil {
				return constants.SIGNATURE_FAILED, err
			}

			signer, err = openpgp.CheckDetachedSignature(pubKeyEntries, origText, signatureReader, config)
			if err != nil {
				return constants.SIGNATURE_FAILED, err
			}
		}
	}

	if signer == nil {
		return constants.SIGNATURE_FAILED, errors.New("gopenpgp: signer is empty")
	}
	// if signer.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
	// 	// t.Errorf("wrong signer got:%x want:%x", signer.PrimaryKey.KeyId, 0)
	// 	return false, errors.New("signer is nil")
	// }
	return constants.SIGNATURE_OK, nil
}
