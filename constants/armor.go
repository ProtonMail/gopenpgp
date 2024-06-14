// Package constants provides a set of common OpenPGP constants.
package constants

// Constants for armored data.
const (
	// ArmorChecksumEnabled defines the default behavior for adding an armor checksum
	// to an armored message.
	//
	// If set to true, an armor checksum is added to the message.
	//
	// If set to false, no armor checksum is added.
	ArmorChecksumEnabled = true
	ArmorHeaderEnabled   = false // can be enabled for debugging at compile time only
	ArmorHeaderVersion   = "GopenPGP " + Version
	ArmorHeaderComment   = "https://gopenpgp.org"
	PGPMessageHeader     = "PGP MESSAGE"
	PGPSignatureHeader   = "PGP SIGNATURE"
	PublicKeyHeader      = "PGP PUBLIC KEY BLOCK"
	PrivateKeyHeader     = "PGP PRIVATE KEY BLOCK"
)
