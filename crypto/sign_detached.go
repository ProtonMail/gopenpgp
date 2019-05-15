package crypto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/internal"

	"golang.org/x/crypto/openpgp"
	errorsPGP "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

// SignTextDetached signs detached text type
func (kr *KeyRing) SignTextDetached(plainText string, passphrase string, trimNewlines bool) (string, error) {
	signEntity, err := kr.GetSigningEntity(passphrase)
	if err != nil {
		return "", err
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pgp.getTimeGenerator()}

	if trimNewlines {
		plainText = internal.TrimNewlines(plainText)
	}

	att := strings.NewReader(plainText)

	var outBuf bytes.Buffer
	//SignText
	if err := openpgp.ArmoredDetachSignText(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// SignBinDetached Signs detached bin data using string key
func (kr *KeyRing) SignBinDetached(plainData []byte, passphrase string) (string, error) {
	//sign with 0x00
	signEntity, err := kr.GetSigningEntity(passphrase)
	if err != nil {
		return "", err
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: pgp.getTimeGenerator()}

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
func (kr *KeyRing) VerifyTextDetachedSig(
	signature string, plainText string, verifyTime int64, trimNewlines bool,
) (bool, error) {
	if trimNewlines {
		plainText = internal.TrimNewlines(plainText)
	}
	origText := bytes.NewReader(bytes.NewBufferString(plainText).Bytes())

	return verifySignature(kr.GetEntities(), origText, signature, verifyTime)
}

// VerifyBinDetachedSig verifies detached text in binary format
// - check if signature is valid using a given publicKey in binary format
func (kr *KeyRing) VerifyBinDetachedSig(signature string, plainData []byte, verifyTime int64) (bool, error) {
	origText := bytes.NewReader(plainData)

	return verifySignature(kr.GetEntities(), origText, signature, verifyTime)
}

// Internal
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
		return false, errors.New("gopenpgp: signer is empty")
	}
	// if signer.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
	// 	// t.Errorf("wrong signer got:%x want:%x", signer.PrimaryKey.KeyId, 0)
	// 	return false, errors.New("signer is nil")
	// }
	return true, nil
}
