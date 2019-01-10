// This package contains a set of helper methods for armoring and unarmoring
package armor

import (
	"bytes"
	"errors"
	"github.com/ProtonMail/go-pm-crypto/internal"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"io"
	"io/ioutil"
)

// Use: ios/android only
// ArmorKey make bytes input key to armor format
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, PUBLIC_KEY_HEADER)
}

// Use: go-pm-crypto, keyring.go
// ArmorWithTypeBuffered take input from io.Writer and returns io.WriteCloser which can be read for armored code
func ArmorWithTypeBuffered(w io.Writer, armorType string) (io.WriteCloser, error) {
	return armor.Encode(w, armorType, nil)
}

// Use: go-pm-crypto
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

// Use: go-pm-crypto, attachment.go, keyring.go, session.go, message.go
// Unarmor an armored key to bytes key
func Unarmor(input string) ([]byte, error) {
	b, err := internal.Unarmor(input)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(b.Body)
}

// Use: ios/android only
//ReadClearSignedMessage read clear message from a clearsign package (package containing cleartext and signature)
func ReadClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", errors.New("pmapi: extra data after modulus")
	}
	return string(modulusBlock.Bytes), nil
}
