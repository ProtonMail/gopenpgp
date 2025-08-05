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

func TestFowardingKeyCheck(t *testing.T) {
	forwardingKey, err := NewKeyFromArmored(readTestFile("key_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	nonForwardingKey, err := NewKeyFromArmored(readTestFile("keyring_userKey", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	if !forwardingKey.IsForwardingKey() {
		t.Fatal("Expected a forwarding key")
	}

	if nonForwardingKey.IsForwardingKey() {
		t.Fatal("Expected non-forwarding key")
	}

	kr, err := NewKeyRing(forwardingKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := kr.AddKey(nonForwardingKey); err != nil {
		t.Fatal(err)
	}

	krWithoutForwarding, err := kr.WithoutForwardingKeys()
	if err != nil {
		t.Fatal(err)
	}

	assert.Exactly(t, krWithoutForwarding.CountEntities(), 1)

	key, err := krWithoutForwarding.GetKey(0)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, !key.IsForwardingKey())
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
		SignTime(1679044110).
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
		VerifyTime(1679044110).
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
