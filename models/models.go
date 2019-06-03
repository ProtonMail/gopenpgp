// Package models provides structs containing message data.
package models

// EncryptedSigned contains an encrypted message and signature.
type EncryptedSigned struct {
	Encrypted string
	Signature string
}
