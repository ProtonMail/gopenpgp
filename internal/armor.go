package internal

import (
	"strings"

	"golang.org/x/crypto/openpgp/armor"
)

// Unarmor unarmors an armored string.
func Unarmor(input string) (*armor.Block, error) {
	io := strings.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, err
	}
	return b, nil
}
