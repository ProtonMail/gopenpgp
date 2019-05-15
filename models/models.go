// Package models provides structs containing message data.
package models

// EncryptedSplit contains a separate session key packet and symmetrically
// encrypted data packet.
type EncryptedSplit struct {
	DataPacket []byte
	KeyPacket  []byte
	Algo       string
}

// EncryptedSigned contains an encrypted message and signature.
type EncryptedSigned struct {
	Encrypted string
	Signature string
}
