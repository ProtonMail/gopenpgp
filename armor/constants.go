package armor

import (
	"gitlab.com/ProtonMail/go-pm-crypto/internal"
)

const (
	ARMOR_HEADER_VERSION        = internal.ARMOR_HEADER_VERSION
	ARMOR_HEADER_COMMENT        = internal.ARMOR_HEADER_COMMENT
	MESSAGE_HEADER       string = "PGP MESSAGE"
	PUBLIC_KEY_HEADER    string = "PGP PUBLIC KEY BLOCK"
	PRIVATE_KEY_HEADER   string = "PGP PRIVATE KEY BLOCK"
)
