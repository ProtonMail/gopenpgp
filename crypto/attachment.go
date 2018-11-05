package crypto

import (
	"bytes"
	"io"
	"io/ioutil"

	armorUtils "github.com/ProtonMail/go-pm-crypto/armor"
	"github.com/ProtonMail/go-pm-crypto/internal"
	"github.com/ProtonMail/go-pm-crypto/models"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// Encrypt attachment. Takes input data and key data in binary form
func (pm *PmCrypto) EncryptAttachmentBinKey(plainData []byte, fileName string, publicKey []byte) (*models.EncryptedSplit, error) {

	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, armorUtils.PGP_MESSAGE_HEADER, internal.ArmorHeaders)
	if err != nil {
		return nil, err
	}

	pubKeyReader := bytes.NewReader(publicKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return nil, err
	}
	hints := &openpgp.FileHints{
		FileName: fileName,
	}

	config := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		Time:          pm.getTimeGenerator(),
	}

	ew, err := openpgp.Encrypt(w, pubKeyEntries, nil, hints, config)

	_, _ = ew.Write(plainData)
	ew.Close()
	w.Close()

	split, err := SplitArmor(outBuf.String())
	if err != nil {
		return nil, err
	}
	split.Algo = "aes256"
	return split, nil
}

// Helper method. Splits armored pgp session into key and packet data
func SplitArmor(encrypted string) (*models.EncryptedSplit, error) {

	var err error

	encryptedRaw, err := armorUtils.Unarmor(encrypted)
	if err != nil {
		return nil, err
	}

	encryptedReader := bytes.NewReader(encryptedRaw)

	return SeparateKeyAndData(nil, encryptedReader)

}

// Encrypt attachment. Takes input data in binary form and key in as a string
func (pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey string) (*models.EncryptedSplit, error) {
	rawPubKey, err := armorUtils.Unarmor(publicKey)
	if err != nil {
		return nil, err
	}
	return pm.EncryptAttachmentBinKey(plainData, fileName, rawPubKey)
}

// Decrypt attachment. Takes input data and key data in binary form. privateKeys can contains more keys. passphrase is used to unlock keys
func (pm *PmCrypto) DecryptAttachmentBinKey(keyPacket []byte, dataPacket []byte, privateKeys []byte, passphrase string) ([]byte, error) {
	privKeyRaw := bytes.NewReader(privateKeys)
	privKeyEntries, err := openpgp.ReadKeyRing(privKeyRaw)
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

	keyReader := bytes.NewReader(keyPacket)
	dataReader := bytes.NewReader(dataPacket)

	encryptedReader := io.MultiReader(keyReader, dataReader)

	config := &packet.Config{Time: pm.getTimeGenerator()}

	md, err := openpgp.ReadMessage(encryptedReader, privKeyEntries, nil, config)
	if err != nil {
		return nil, err
	}

	decrypted := md.UnverifiedBody
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Decrypt attachment. Takes input data and key data in binary form and key as an armored string. passphrase is used to unlock keys
func (pm *PmCrypto) DecryptAttachment(keyPacket []byte, dataPacket []byte, privateKey string, passphrase string) ([]byte, error) {
	rawPrivKey, err := armorUtils.Unarmor(privateKey)
	if err != nil {
		return nil, err
	}
	return pm.DecryptAttachmentBinKey(keyPacket, dataPacket, rawPrivKey, passphrase)
}

//Encrypt attachment. Use symmetrical cipher with key in password input string
func (pm *PmCrypto) EncryptAttachmentWithPassword(plainData []byte, password string) (string, error) {

	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, armorUtils.PGP_MESSAGE_HEADER, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}

	config := &packet.Config{Time: pm.getTimeGenerator()}

	plaintext, err := openpgp.SymmetricallyEncrypt(w, []byte(password), nil, config)
	if err != nil {
		return "", err
	}

	_, err = plaintext.Write(plainData)
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

//Decrypt attachment using password locked key.
func (pm *PmCrypto) DecryptAttachmentWithPassword(keyPacket []byte, dataPacket []byte, password string) ([]byte, error) {

	encrypted := append(keyPacket, dataPacket...)

	encryptedReader := bytes.NewReader(encrypted)

	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return []byte(password), nil
	}

	config := &packet.Config{Time: pm.getTimeGenerator()}

	md, err := openpgp.ReadMessage(encryptedReader, nil, prompt, config)
	if err != nil {
		return nil, err
	}

	messageBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(messageBuf, md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	return messageBuf.Bytes(), nil
}
