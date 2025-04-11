package internal

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Unarmor unarmors an armored string.
func Unarmor(input string) (*armor.Block, error) {
	io := strings.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, fmt.Errorf("gopenpgp: unable to unarmor: %w", err)
	}
	return b, nil
}

// UnarmorBytes unarmors an armored byte slice.
func UnarmorBytes(input []byte) (*armor.Block, error) {
	io := bytes.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, fmt.Errorf("gopenpgp: unable to unarmor: %w", err)
	}
	return b, nil
}
