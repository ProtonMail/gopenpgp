package crypto

import (
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"testing"
)

func TestSubtle_EncryptWithoutIntegrity(t *testing.T) {
	key, _ := hex.DecodeString("9469cccfc8a8d005247f39fa3e5b35a97db456cecf18deac6d84364d0818d763")
	plaintext := []byte("some plaintext")
	iv, _ := hex.DecodeString("c828f258a76aad7bc828f258a76aad7b")

	ciphertext, _ := EncryptWithoutIntegrity(key, plaintext, iv)
	assert.Exactly(t, "14697192f7e112fc88d83380693f", hex.EncodeToString(ciphertext))
}

func TestSubtle_DecryptWithoutIntegrity(t *testing.T) {
	key, _ := hex.DecodeString("9469cccfc8a8d005247f39fa3e5b35a97db456cecf18deac6d84364d0818d763")
	ciphertext, _ := hex.DecodeString("14697192f7e112fc88d83380693f")
	iv, _ := hex.DecodeString("c828f258a76aad7bc828f258a76aad7b")

	plaintext, _ := DecryptWithoutIntegrity(key, ciphertext, iv)
	assert.Exactly(t, "some plaintext", string(plaintext))
}

func TestSubtle_DeriveKey(t *testing.T) {
	salt, _ := hex.DecodeString("c828f258a76aad7b")
	dk, _ := DeriveKey("some password", salt, 32768)
	assert.Exactly(t, "9469cccfc8a8d005247f39fa3e5b35a97db456cecf18deac6d84364d0818d763", hex.EncodeToString(dk))
}
