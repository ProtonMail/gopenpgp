package internal

import (
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
