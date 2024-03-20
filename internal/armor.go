package internal

import (
	"bytes"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/pkg/errors"
)

// Unarmor unarmors an armored string.
func Unarmor(input string) (*armor.Block, error) {
	io := strings.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to unarmor")
	}
	return b, nil
}

// UnarmorBytes unarmors an armored byte slice.
func UnarmorBytes(input []byte) (*armor.Block, error) {
	io := bytes.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to unarmor")
	}
	return b, nil
}
