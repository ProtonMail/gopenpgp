// Package constants provides a set of common OpenPGP constants.
package constants

// Constants for armored data.
const (
	ArmorHeaderVersion = "GopenPGP 0.0.1 (" + Version + ")"
	ArmorHeaderComment = "https://gopenpgp.org"
	PGPMessageHeader   = "PGP MESSAGE"
	PGPSignatureHeader = "PGP SIGNATURE"
	PublicKeyHeader    = "PGP PUBLIC KEY BLOCK"
	PrivateKeyHeader   = "PGP PRIVATE KEY BLOCK"
)
