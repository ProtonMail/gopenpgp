package pm

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// DecryptMessage decrypt encrypted message use private key (string )
// encryptedText : string armored encrypted
// privateKey : armored private use to decrypt message
// passphrase : match with private key to decrypt message
func (o *OpenPGP) DecryptMessage(encryptedText string, privateKey string, passphrase string) (string, error) {
	privKeyRaw, err := UnArmor(privateKey)
	if err != nil {
		return "", err
	}
	return o.DecryptMessageBinKey(encryptedText, privKeyRaw, passphrase)
}

// DecryptMessageBinKey decrypt encrypted message use private key (bytes )
// encryptedText : string armored encrypted
// privateKey : unarmored private use to decrypt message
// passphrase : match with private key to decrypt message
func (o *OpenPGP) DecryptMessageBinKey(encryptedText string, privateKey []byte, passphrase string) (string, error) {
	privKey := bytes.NewReader(privateKey)
	privKeyEntries, err := openpgp.ReadKeyRing(privKey)
	if err != nil {
		return "", err
	}

	encryptedio, err := unArmor(encryptedText)
	if err != nil {
		return "", err
	}

	rawPwd := []byte(passphrase)
	for _, e := range privKeyEntries {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			e.PrivateKey.Decrypt(rawPwd)
		}

		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				sub.PrivateKey.Decrypt(rawPwd)
			}
		}
	}

	md, err := openpgp.ReadMessage(encryptedio.Body, privKeyEntries, nil, nil)
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

// encryptedText string, privateKey string, passphrase string) (string, error)
// decrypt_message_verify_single_key(private_key: string, passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
// decrypt_message_verify(passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
func (o *OpenPGP) DecryptMessageVerifyPrivbinkeys(encryptedText string, veriferKey string, privateKeys []byte, passphrase string, verifyTime int64) (*DecryptSignedVerify, error) {

	if len(veriferKey) > 0 {
		verifierRaw, err := UnArmor(veriferKey)
		if err != nil {
			return nil, err
		}
		return o.decryptMessageVerifyAllBin(encryptedText, verifierRaw, privateKeys, passphrase, verifyTime)
	}
	return o.decryptMessageVerifyAllBin(encryptedText, nil, privateKeys, passphrase, verifyTime)
}

// encryptedText string, privateKey string, passphrase string) (string, error)
// decrypt_message_verify_single_key(private_key: string, passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
// decrypt_message_verify(passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
func (o *OpenPGP) DecryptMessageVerifyBinKeyPrivbinkeys(encryptedText string, veriferKey []byte, privateKeys []byte, passphrase string, verifyTime int64) (*DecryptSignedVerify, error) {
	return o.decryptMessageVerifyAllBin(encryptedText, veriferKey, privateKeys, passphrase, verifyTime)
}

// encryptedText string, privateKey string, passphrase string) (string, error)
// decrypt_message_verify_single_key(private_key: string, passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
// decrypt_message_verify(passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
func (o *OpenPGP) DecryptMessageVerify(encryptedText string, veriferKey string, privateKey string, passphrase string, verifyTime int64) (*DecryptSignedVerify, error) {
	if len(veriferKey) > 0 {
		verifierRaw, err := UnArmor(veriferKey)
		if err != nil {
			return nil, err
		}
		return o.DecryptMessageVerifyBinKey(encryptedText, verifierRaw, privateKey, passphrase, verifyTime)
	}
	return o.DecryptMessageVerifyBinKey(encryptedText, nil, privateKey, passphrase, verifyTime)
}

// encryptedText string, privateKey string, passphrase string) (string, error)
// decrypt_message_verify_single_key(private_key: string, passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
// decrypt_message_verify(passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
func (o *OpenPGP) DecryptMessageVerifyBinKey(encryptedText string, veriferKey []byte, privateKey string, passphrase string, verifyTime int64) (*DecryptSignedVerify, error) {
	privateKeyRaw, err := UnArmor(privateKey)
	if err != nil {
		return nil, err
	}
	return o.decryptMessageVerifyAllBin(encryptedText, veriferKey, privateKeyRaw, passphrase, verifyTime)
}

// encryptedText string, privateKey string, passphrase string) (string, error)
// decrypt_message_verify_single_key(private_key: string, passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
// decrypt_message_verify(passphras: string, encrypted : string, signature : string) : decrypt_sign_verify;
func (o *OpenPGP) decryptMessageVerifyAllBin(encryptedText string, veriferKey []byte, privateKey []byte, passphrase string, verifyTime int64) (*DecryptSignedVerify, error) {
	privKey := bytes.NewReader(privateKey)
	privKeyEntries, err := openpgp.ReadKeyRing(privKey)
	if err != nil {
		return nil, err
	}

	rawPwd := []byte(passphrase)
	for _, e := range privKeyEntries {

		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			e.PrivateKey.Decrypt(rawPwd)
		}

		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				sub.PrivateKey.Decrypt(rawPwd)
			}
		}
	}

	out := &DecryptSignedVerify{}
	out.Verify = failed

	if len(veriferKey) > 0 {
		verifierReader := bytes.NewReader(veriferKey)
		verifierEnties, err := openpgp.ReadKeyRing(verifierReader)
		if err != nil {
			return nil, err
		}

		for _, e := range verifierEnties {
			privKeyEntries = append(privKeyEntries, e)
		}
	} else {
		out.Verify = noVerifier
	}

	encryptedio, err := unArmor(encryptedText)
	if err != nil {
		return nil, err
	}

	config := &packet.Config{}
	if verifyTime > 0 {
		tm := time.Unix(verifyTime, 0)
		config.Time = func() time.Time {
			return tm
		}
	}

	md, err := openpgp.ReadMessage(encryptedio.Body, privKeyEntries, nil, config)
	if err != nil {
		return nil, err
	}

	decrypted := md.UnverifiedBody
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return nil, err
	}

	out.Plaintext = string(b)
	if md.IsSigned {
		if md.SignedBy != nil {
			if md.SignatureError == nil {
				out.Verify = ok
			} else {
				out.Message = md.SignatureError.Error()
				out.Verify = failed
			}
		} else {
			out.Verify = noVerifier
		}
	} else {
		out.Verify = notSigned
	}
	return out, nil
}

// EncryptMessage encrypt message with public key, if pass private key and passphrase will also sign the message
// publicKey : string armored public key
// plainText : the input
// privateKey : optional required when you want to sign
// passphrase : optional required when you pass the private key and this passphrase must could decrypt the private key
func (o *OpenPGP) EncryptMessage(plainText string, publicKey string, privateKey string, passphrase string, trim bool) (string, error) {
	rawPubKey, err := UnArmor(publicKey)
	if err != nil {
		return "", err
	}
	return o.EncryptMessageBinKey(plainText, rawPubKey, privateKey, passphrase, trim)
}

// EncryptMessageBinKey encrypt message with public key, if pass private key and passphrase will also sign the message
// publicKey : bytes unarmored public key
// plainText : the input
// privateKey : optional required when you want to sign
// passphrase : optional required when you pass the private key and this passphrase must could decrypt the private key
func (o *OpenPGP) EncryptMessageBinKey(plainText string, publicKey []byte, privateKey string, passphrase string, trim bool) (string, error) {

	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, pgpMessageType.string(), armorHeader)
	if err != nil {
		return "", err
	}

	pubKeyReader := bytes.NewReader(publicKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return "", err
	}

	var signEntity *openpgp.Entity

	if len(passphrase) > 0 && len(privateKey) > 0 {
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
	}

	config := &packet.Config{DefaultCipher: packet.CipherAES256}

	ew, err := openpgp.Encrypt(w, pubKeyEntries, signEntity, nil, config)

	_, _ = ew.Write([]byte(plainText))
	ew.Close()
	w.Close()
	return outBuf.String(), nil
}

//EncryptMessageWithPassword ...
func (o *OpenPGP) EncryptMessageWithPassword(plainText string, password string) (string, error) {

	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, pgpMessageType.string(), armorHeader)
	if err != nil {
		return "", err
	}

	plaintext, err := openpgp.SymmetricallyEncrypt(w, []byte(password), nil, nil)
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

//DecryptMessageWithPassword ...
func (o *OpenPGP) DecryptMessageWithPassword(encrypted string, password string) (string, error) {

	encryptedio, err := unArmor(encrypted)
	if err != nil {
		return "", err
	}

	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return []byte(password), nil
	}

	md, err := openpgp.ReadMessage(encryptedio.Body, nil, prompt, nil)
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
