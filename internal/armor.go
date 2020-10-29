package internal

import (
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp/armor"
)

// Unarmor unarmors an armored string.
func Unarmor(input string) (*armor.Block, error) {
	io := strings.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to armor")
	}
	return b, nil
}
