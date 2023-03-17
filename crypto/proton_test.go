package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForwardeeDecryption(t *testing.T) {
	//pgp.latestServerTime = 1679044110

	forwardeeKey, err := NewKeyFromArmored(readTestFile("key_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	forwardeeKeyRing, err := NewKeyRing(forwardeeKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	pgpMessage := readTestFile("message_forwardee", false)
	decryptor, err := PGP().Decryption().
		DecryptionKeys(forwardeeKeyRing).
		VerifyTime(1679044110).
		New()
	if err != nil {
		t.Fatal(err)
	}
	plainMessage, err := decryptor.Decrypt([]byte(pgpMessage), Armor)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "Message for Bob", plainMessage.String())
}

func TestSymmetricKeys(t *testing.T) {
	symmetricKey, err := NewKeyFromArmored(readTestFile("key_symmetric", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	symmetricKeyRing, err := NewKeyRing(symmetricKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	pgp := PGP()
	encryptor, err := pgp.Encryption().
		Recipients(symmetricKeyRing).
		SignTime(1731431813).
		New()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encryptor.Encrypt(binData)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decryptor, err := pgp.Decryption().
		DecryptionKeys(symmetricKeyRing).
		VerifyTime(1731431813).
		New()
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptor.Decrypt(ciphertext.Bytes(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, binData, decrypted.Bytes())
}
