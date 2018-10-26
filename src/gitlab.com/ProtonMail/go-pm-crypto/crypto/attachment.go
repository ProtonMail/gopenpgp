package crypto

import (
	"bytes"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	armorUtils "gitlab.com/ProtonMail/go-pm-crypto/armor"
	"gitlab.com/ProtonMail/go-pm-crypto/internal"
	"gitlab.com/ProtonMail/go-pm-crypto/models"
		"sync"
	)

//EncryptAttachmentBinKey ...
func (pm *PmCrypto) EncryptAttachmentBinKey(plainData []byte, fileName string, publicKey []byte) (*models.EncryptedSplit, error) {
	var wg sync.WaitGroup
	// you can also add these one at
	// a time if you need to
	wg.Add(1)
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

	reader, writer := io.Pipe()
	var encryptErr error
	go func() {
		defer wg.Done()
		var ew io.WriteCloser
		ew, encryptErr = openpgp.Encrypt(writer, pubKeyEntries, nil, hints, config)
		_, _ = ew.Write(plainData)
		plainData = nil
		// clear the buffer
		ew.Close()
		writer.Close()
	}()

	split, err := internal.SplitPackets(reader, len(plainData))

	wg.Wait()
	if encryptErr != nil {
		return nil, encryptErr
	}

	if err != nil {
		return nil, err
	}
	split.Algo = "aes256"
	return split, nil
}

//EncryptAttachment ...
func (pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey string) (*models.EncryptedSplit, error) {
	rawPubKey, err := armorUtils.Unarmor(publicKey)
	if err != nil {
		return nil, err
	}
	return pm.EncryptAttachmentBinKey(plainData, fileName, rawPubKey)
}

//DecryptAttachmentBinKey ...
//keyPacket
//dataPacket
//privateKeys could be mutiple private keys
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

//DecryptAttachment ...
func (pm *PmCrypto) DecryptAttachment(keyPacket []byte, dataPacket []byte, privateKey string, passphrase string) ([]byte, error) {
	rawPrivKey, err := armorUtils.Unarmor(privateKey)
	if err != nil {
		return nil, err
	}
	return pm.DecryptAttachmentBinKey(keyPacket, dataPacket, rawPrivKey, passphrase)
}

//EncryptAttachmentWithPassword ...
func (pm *PmCrypto) EncryptAttachmentWithPassword(plainData []byte, password string) (string, error) {

	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, armorUtils.MESSAGE_HEADER, internal.ArmorHeaders)
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

//DecryptAttachmentWithPassword ...
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
