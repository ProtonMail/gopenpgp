// Provides high-level public data models used for communication mainly with mobile clients
package models

// EncryptedSplit when encrypt attachment
type EncryptedSplit struct {
	DataPacket []byte
	KeyPacket  []byte
	Algo       string
}

// EncryptedSigned encrypt_sign_package
type EncryptedSigned struct {
	Encrypted string
	Signature string
}

// DecryptSignedVerify decrypt_sign_verify
type DecryptSignedVerify struct {
	//clear text
	Plaintext string
	//bitmask verify status : 0
	Verify int
	//error message if verify failed
	Message string
}
