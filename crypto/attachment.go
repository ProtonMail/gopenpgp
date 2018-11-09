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
func (pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey *KeyRing) (*models.EncryptedSplit, error) {
	var outBuf bytes.Buffer
	w, err := armor.Encode(&outBuf, armorUtils.PGP_MESSAGE_HEADER, internal.ArmorHeaders)
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

	ew, err := openpgp.Encrypt(w, publicKey.entities, nil, hints, config)

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

// Decrypt attachment. Takes input data and key data in binary form. privateKeys can contains more keys. passphrase is used to unlock keys
func (pm *PmCrypto) DecryptAttachment(keyPacket []byte, dataPacket []byte, kr *KeyRing, passphrase string) ([]byte, error) {

	privKeyEntries := kr.entities

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
