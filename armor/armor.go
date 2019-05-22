// Package armor contains a set of helper methods for armoring and unarmoring
// data.
package armor

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/internal"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
)

// ArmorKey armors input as a public key.
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, constants.PublicKeyHeader)
}

// ArmorWithTypeBuffered returns a io.WriteCloser which, when written to, writes
// armored data to w with the given armorType.
func ArmorWithTypeBuffered(w io.Writer, armorType string) (io.WriteCloser, error) {
	return armor.Encode(w, armorType, nil)
}

// ArmorWithType armors input with the given armorType.
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

// Unarmor unarmors an armored key.
func Unarmor(input string) ([]byte, error) {
	b, err := internal.Unarmor(input)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(b.Body)
}

// ReadClearSignedMessage returns the message body and unarmored signature from a clearsigned message.
func ReadClearSignedMessage(signedMessage string) (string, []byte, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", nil, errors.New("pmapi: extra data after modulus")
	}

	signature, err := ioutil.ReadAll(modulusBlock.ArmoredSignature.Body)
	if err != nil {
		return "", nil, err
	}

	return string(modulusBlock.Bytes), signature, nil
}

// ArmorClearSignedMessage armors plaintext and signature with the PGP SIGNED MESSAGE armoring
func ArmorClearSignedMessage(plaintext []byte, signature []byte) (string, error) {
	armSignature, err := ArmorWithType(signature, constants.PGPSignatureHeader)
	if err != nil {
		return "", err
	}

	str := "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash:SHA512\r\n\r\n"
	str += string(plaintext)
	str += "\r\n"
	str += armSignature

	return str, nil
}
