package pm

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
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

	config := &packet.Config{DefaultCipher: packet.CipherAES256}

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

	config := &packet.Config{DefaultCipher: packet.CipherAES256}

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

	config := &packet.Config{DefaultCipher: packet.CipherAES256}

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

	config := &packet.Config{DefaultCipher: packet.CipherAES256}

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

	signatureReader := strings.NewReader(signature)

	origText := bytes.NewReader(bytes.NewBufferString(plainText).Bytes())

	config := &packet.Config{}
	if verifyTime > 0 {
		tm := time.Unix(verifyTime, 0)
		config.Time = func() time.Time {
			return tm
		}
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)
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

// VerifyTextSignDetachedBinKey ...
func (o *OpenPGP) VerifyTextSignDetachedBinKey(signature string, plainText string, publicKey []byte, verifyTime int64) (bool, error) {

	pubKeyReader := bytes.NewReader(publicKey)

	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return false, err
	}

	signatureReader := strings.NewReader(signature)

	origText := bytes.NewReader(bytes.NewBufferString(plainText).Bytes())
	config := &packet.Config{}
	if verifyTime > 0 {
		tm := time.Unix(verifyTime, 0)
		config.Time = func() time.Time {
			return tm
		}
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)
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

	signatureReader := strings.NewReader(signature)

	origText := bytes.NewReader(plainData)
	config := &packet.Config{}
	if verifyTime > 0 {
		tm := time.Unix(verifyTime, 0)
		config.Time = func() time.Time {
			return tm
		}
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)
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

// VerifyBinSignDetachedBinKey ...
func (o *OpenPGP) VerifyBinSignDetachedBinKey(signature string, plainData []byte, publicKey []byte, verifyTime int64) (bool, error) {
	pubKeyReader := bytes.NewReader(publicKey)

	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return false, err
	}

	signatureReader := strings.NewReader(signature)

	origText := bytes.NewReader(plainData)

	config := &packet.Config{}
	if verifyTime > 0 {
		tm := time.Unix(verifyTime, 0)
		config.Time = func() time.Time {
			return tm
		}
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(pubKeyEntries, origText, signatureReader, config)
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
