package pmcrypto

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
	errors2 "golang.org/x/crypto/openpgp/errors"
	"io"
)

//ReadClearSignedMessage read clear message from a clearsign package
func ReadClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", errors.New("pmapi: extra data after modulus")
	}
	return string(modulusBlock.Bytes), nil
}

// SignTextDetached sign detached text type
func (o *OpenPGP) SignTextDetached(plainText string, privateKey string, passphrase string, trim bool) (string, error) {
	//sign with 0x01 text
	var signEntity *openpgp.Entity

	if trim {
		plainText = trimNewlines(plainText)
	}

	signerReader := strings.NewReader(privateKey)
	signerEntries, err := openpgp.ReadArmoredKeyRing(signerReader)
	if err != nil {
		return "", err
	}

	for _, e := range signerEntries {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			if e.PrivateKey.Encrypted {
				e.PrivateKey.Decrypt([]byte(passphrase))
			}
			if !e.PrivateKey.Encrypted {
				signEntity = e
				break
			}
		}
	}

	if signEntity == nil {
		return "", errors.New("cannot sign message, signer key is not unlocked")
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: o.getTimeGenerator() }

	att := strings.NewReader(plainText)

	var outBuf bytes.Buffer
	//SignText
	if err = openpgp.ArmoredDetachSignText(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// SignTextDetachedBinKey ...
func (o *OpenPGP) SignTextDetachedBinKey(plainText string, privateKey []byte, passphrase string, trim bool) (string, error) {
	//sign with 0x01
	var signEntity *openpgp.Entity

	if trim {
		plainText = trimNewlines(plainText)
	}

	signerReader := bytes.NewReader(privateKey)
	signerEntries, err := openpgp.ReadKeyRing(signerReader)
	if err != nil {
		return "", err
	}

	for _, e := range signerEntries {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			if e.PrivateKey.Encrypted {
				e.PrivateKey.Decrypt([]byte(passphrase))
			}
			if !e.PrivateKey.Encrypted {
				signEntity = e
				break
			}
		}
	}

	if signEntity == nil {
		return "", errors.New("cannot sign message, singer key is not unlocked")
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: o.getTimeGenerator() }

	att := strings.NewReader(plainText)

	var outBuf bytes.Buffer
	//sign text
	if err = openpgp.ArmoredDetachSignText(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// SignBinDetached sign bin data
func (o *OpenPGP) SignBinDetached(plainData []byte, privateKey string, passphrase string) (string, error) {
	//sign with 0x00
	var signEntity *openpgp.Entity

	signerReader := strings.NewReader(privateKey)
	signerEntries, err := openpgp.ReadArmoredKeyRing(signerReader)
	if err != nil {
		return "", err
	}

	for _, e := range signerEntries {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			if e.PrivateKey.Encrypted {
				e.PrivateKey.Decrypt([]byte(passphrase))
			}
			if !e.PrivateKey.Encrypted {
				signEntity = e
				break
			}
		}
	}

	if signEntity == nil {
		return "", errors.New("cannot sign message, singer key is not unlocked")
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: o.getTimeGenerator() }

	att := bytes.NewReader(plainData)

	var outBuf bytes.Buffer
	//sign bin
	if err = openpgp.ArmoredDetachSign(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// SignBinDetachedBinKey ...
func (o *OpenPGP) SignBinDetachedBinKey(plainData []byte, privateKey []byte, passphrase string) (string, error) {
	//sign with 0x00
	var signEntity *openpgp.Entity

	signerReader := bytes.NewReader(privateKey)
	signerEntries, err := openpgp.ReadKeyRing(signerReader)
	if err != nil {
		return "", err
	}

	for _, e := range signerEntries {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			if e.PrivateKey.Encrypted {
				e.PrivateKey.Decrypt([]byte(passphrase))
			}
			if !e.PrivateKey.Encrypted {
				signEntity = e
				break
			}
		}
	}

	if signEntity == nil {
		return "", errors.New("cannot sign message, singer key is not unlocked")
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: o.getTimeGenerator() }

	att := bytes.NewReader(plainData)

	var outBuf bytes.Buffer
	//sign bin
	if err = openpgp.ArmoredDetachSign(&outBuf, signEntity, att, config); err != nil {
		return "", err
	}

	return outBuf.String(), nil
}

// VerifyTextSignDetached ...
func (o *OpenPGP) VerifyTextSignDetached(signature string, plainText string, publicKey string, verifyTime int64) (bool, error) {

	pubKeyReader := strings.NewReader(publicKey)

	pubKeyEntries, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return false, err
	}

	plainText = trimNewlines(plainText)

	origText := bytes.NewReader(bytes.NewBufferString(plainText).Bytes())

	return verifySignature(pubKeyEntries, origText, signature, verifyTime)
}

// VerifyTextSignDetachedBinKey ...
func (o *OpenPGP) VerifyTextSignDetachedBinKey(signature string, plainText string, publicKey []byte, verifyTime int64) (bool, error) {

	pubKeyReader := bytes.NewReader(publicKey)

	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return false, err
	}

	plainText = trimNewlines(plainText)
	origText := bytes.NewReader(bytes.NewBufferString(plainText).Bytes())

	return verifySignature(pubKeyEntries, origText, signature, verifyTime)
}

func verifySignature(pubKeyEntries openpgp.EntityList, origText *bytes.Reader, signature string, verifyTime int64) (bool, error) {
	config := &packet.Config{}
	if verifyTime == 0 {
		config.Time = func() time.Time {
			return time.Unix(0, 0)
		}
	} else {
		config.Time = func() time.Time {
			return time.Unix(verifyTime + creationTimeOffset, 0)
		}
	}
	signatureReader := strings.NewReader(signature)

	signer, err := openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)

	if err == errors2.ErrSignatureExpired && signer != nil {
		if verifyTime > 0 {
			// Maybe the creation time offset pushed it over the edge
			// Retry with the actual verification time
			config.Time = func() time.Time {
				return time.Unix(verifyTime, 0)
			}

			signatureReader.Seek(0, io.SeekStart)
			signer, err = openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)
		} else {
			// verifyTime = 0: time check disabled, everything is okay
			err = nil
		}
	}
	if err != nil {
		return false, err
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


// VerifyBinSignDetached ...
func (o *OpenPGP) VerifyBinSignDetached(signature string, plainData []byte, publicKey string, verifyTime int64) (bool, error) {

	pubKeyReader := strings.NewReader(publicKey)

	pubKeyEntries, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return false, err
	}

	origText := bytes.NewReader(plainData)
	return verifySignature(pubKeyEntries, origText, signature, verifyTime)
}

// VerifyBinSignDetachedBinKey ...
func (o *OpenPGP) VerifyBinSignDetachedBinKey(signature string, plainData []byte, publicKey []byte, verifyTime int64) (bool, error) {
	pubKeyReader := bytes.NewReader(publicKey)

	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return false, err
	}

	origText := bytes.NewReader(plainData)

	return verifySignature(pubKeyEntries, origText, signature, verifyTime)
}
