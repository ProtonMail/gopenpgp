package armor

import (
	"bytes"
	"errors"
	"gitlab.com/ProtonMail/go-pm-crypto/internal"
		"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"io/ioutil"
	"gitlab.com/ProtonMail/go-pm-crypto/models"
			)

// ArmorKey make bytes input key to armor format
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, PUBLIC_KEY_HEADER)
}

// ArmorWithType make bytes input to armor format
func ArmorWithType(input []byte, armorType string) (string, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, armorType, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}
	_, err = w.Write(input)
	if err != nil {
		return "", err
	}
	w.Close()
	return b.String(), nil
}

// Unarmor an armored key to bytes key
func Unarmor(input string) ([]byte, error) {
	b, err := internal.Unarmor(input)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(b.Body)
}

//ReadClearSignedMessage read clear message from a clearsign package
func ReadClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", errors.New("pmapi: extra data after modulus")
	}
	return string(modulusBlock.Bytes), nil
}

func SplitArmor(encrypted string) (*models.EncryptedSplit, error) {
	var err error
	b, err := internal.Unarmor(encrypted)
	if err != nil {
		return nil, err
	}
	split, err := internal.SplitPackets(b.Body, len(encrypted), -1)
	if err != nil {
		return nil, err
	}
	return split, nil
}