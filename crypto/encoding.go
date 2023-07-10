package crypto

import (
	"io"

	armorHelper "github.com/ProtonMail/gopenpgp/v3/armor"
)

type PGPEncoding int8

// PGPEncoding determines the message encoding.
// The type is int8 for compatibility with gomobile.
const (
	Armor int8 = 0
	Bytes int8 = 1 // Default for other int8 values.
	Auto  int8 = 2
)

func armorOutput(e int8) bool {
	switch int8(e) {
	case Armor:
		return true
	}
	return false
}

func unarmorInput(e int8, input io.Reader) (reader Reader, unarmor bool) {
	reader = input
	switch int8(e) {
	case Armor:
		unarmor = true
	case Auto:
		reader, unarmor = armorHelper.IsPGPArmored(input)
	}
	return
}
