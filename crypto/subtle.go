package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/scrypt"
)

// EncryptWithoutIntegrity encrypts data with AES-CTR. Note: this encryption mode is not secure when stored/sent on an untrusted medium.
// Use: ios/android only
func EncryptWithoutIntegrity(key, input, iv []byte) (output []byte, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	output = make([]byte, len(input))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(output, input)
	return
}

// DecryptWithoutIntegrity decrypts data encrypted with AES-CTR.
// Use: ios/android only
func DecryptWithoutIntegrity(key, input, iv []byte) ([]byte, error) {
	// AES-CTR decryption is identical to encryption.
	return EncryptWithoutIntegrity(key, input, iv)
}

// DeriveKey derives a key from a password using scrypt. N should be set to the highest power of 2 you can derive within 100 milliseconds.
// Use: ios/android only
func DeriveKey(password string, salt []byte, N int) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, N, 8, 1, 32)
}
