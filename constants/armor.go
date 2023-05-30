// Package constants provides a set of common OpenPGP constants.
package constants

// Constants for armored data.
const (
	ArmorHeaderEnabled = false // can be enabled for debugging at compile time only
	ArmorHeaderVersion = "GopenPGP " + Version
	ArmorHeaderComment = "https://gopenpgp.org"
	PGPMessageHeader   = "PGP MESSAGE"
	PGPSignatureHeader = "PGP SIGNATURE"
	PublicKeyHeader    = "PGP PUBLIC KEY BLOCK"
	PrivateKeyHeader   = "PGP PRIVATE KEY BLOCK"
)
