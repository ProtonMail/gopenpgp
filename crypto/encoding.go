package crypto

import (
	"io"

	armorHelper "github.com/ProtonMail/gopenpgp/v3/armor"
)

type PGPEncoding int8

const (
	Armor PGPEncoding = 0
	Bytes PGPEncoding = 1
	Auto  PGPEncoding = 2
)

func (e PGPEncoding) armorOutput() bool {
	switch e {
	case Armor:
		return true
	}
	return false
}

func (e PGPEncoding) unarmorInput(input io.Reader) (reader Reader, unarmor bool) {
	reader = input
	switch e {
	case Armor:
		unarmor = true
	case Auto:
		reader, unarmor = armorHelper.IsPGPArmored(input)
	}
	return
}
