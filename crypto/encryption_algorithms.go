package crypto

import (
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
)

// defaultEncryptionConfig returns the default cryptography
// configuration for encryption in gopenpgp
func defaultEncryptionConfig() *packet.Config {
	return &packet.Config{
		DefaultCipher: packet.CipherAES256,
		Time:          getTimeGenerator(),
		V6Keys:        constants.EnableV6,
	}
}
