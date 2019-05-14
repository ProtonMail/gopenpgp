package crypto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-pm-crypto/internal"

	"golang.org/x/crypto/openpgp"
	errorsPGP "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

// SignTextDetached signs detached text type
func (pm *PmCrypto) SignTextDetached(
	plainText string, privateKey *KeyRing, passphrase string, trim bool,
) (string, error) {
	//sign with 0x01 text
	if trim {
		plainText = internal.TrimNewlines(plainText)
	}

	signEntity, err := privateKey.GetSigningEntity(passphrase)
	if err != nil {
		return "", err
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pm.getTimeGenerator()}

	att := strings.NewReader(plainText)

	var outBuf bytes.Buffer
	//SignText
	if err := openpgp.ArmoredDetachSignText(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// SignBinDetached Signs detached bin data using string key
func (pm *PmCrypto) SignBinDetached(plainData []byte, privateKey *KeyRing, passphrase string) (string, error) {
	//sign with 0x00
	signEntity, err := privateKey.GetSigningEntity(passphrase)
	if err != nil {
		return "", err
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pm.getTimeGenerator()}

	att := bytes.NewReader(plainData)

	var outBuf bytes.Buffer
	//sign bin
	if err := openpgp.ArmoredDetachSign(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// VerifyTextDetachedSig verifies detached text
// - check if signature is valid using a given publicKey in binary format
func (pm *PmCrypto) VerifyTextDetachedSig(
	signature string, plainText string, publicKey *KeyRing, verifyTime int64,
) (bool, error) {
	plainText = internal.TrimNewlines(plainText)
	origText := bytes.NewReader(bytes.NewBufferString(plainText).Bytes())

	return verifySignature(publicKey.entities, origText, signature, verifyTime)
}

func verifySignature(
	pubKeyEntries openpgp.EntityList, origText *bytes.Reader,
	signature string, verifyTime int64,
) (bool, error) {
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
	signatureReader := strings.NewReader(signature)

	signer, err := openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)

	if err == errorsPGP.ErrSignatureExpired && signer != nil {
		if verifyTime > 0 { // if verifyTime = 0: time check disabled, everything is okay
			// Maybe the creation time offset pushed it over the edge
			// Retry with the actual verification time
			config.Time = func() time.Time {
				return time.Unix(verifyTime, 0)
			}

			_, err = signatureReader.Seek(0, io.SeekStart)
			if err != nil {
				return false, err
			}

			signer, err = openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)
			if err != nil {
				return false, err
			}
		}
	}

	if signer == nil {
		return false, errors.New("signer is empty")
	}
	// if signer.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
	// 	// t.Errorf("wrong signer got:%x want:%x", signer.PrimaryKey.KeyId, 0)
	// 	return false, errors.New("signer is nil")
	// }
	return true, nil
}

// VerifyBinDetachedSig verifies detached text in binary format
// - check if signature is valid using a given publicKey in binary format
func (pm *PmCrypto) VerifyBinDetachedSig(
	signature string, plainData []byte, publicKey *KeyRing, verifyTime int64,
) (bool, error) {
	origText := bytes.NewReader(plainData)

	return verifySignature(publicKey.entities, origText, signature, verifyTime)
}
