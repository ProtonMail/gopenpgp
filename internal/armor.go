package internal

import (
	"golang.org/x/crypto/openpgp/armor"
	"strings"
)

func UnArmor(input string) (*armor.Block, error) {
	io := strings.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, err
	}
	return b, nil

}