package helper

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/crypto"
	"github.com/stretchr/testify/assert"
)

func TestAESEncryption(t *testing.T) {
	var plaintext = "Symmetric secret"
	var passphrase = "passphrase"

	ciphertext, err := EncryptMessageWithPassword(passphrase, plaintext)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	_, err = DecryptMessageWithPassword("Wrong passphrase", ciphertext)
	assert.EqualError(t, err, "gopenpgp: wrong password in symmetric decryption")

	decrypted, err := DecryptMessageWithPassword(passphrase, ciphertext)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestArmoredTextMessageEncryption(t *testing.T) {
	var plaintext = "Secret message"

	armored, err := EncryptMessageArmored(readTestFile("keyring_publicKey", false), plaintext)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, pgp.IsPGPMessage(armored))

	decrypted, err := DecryptMessageArmored(
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		armored,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestArmoredTextMessageEncryptionVerification(t *testing.T) {
	var plaintext = "Secret message"

	armored, err := EncryptSignMessageArmored(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		plaintext,
	)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, pgp.IsPGPMessage(armored))

	_, err = DecryptVerifyMessageArmored(
		readTestFile("mime_publicKey", false), // Wrong public key
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		armored,
	)
	assert.EqualError(t, err, "gopenpgp: unable to verify message")

	decrypted, err := DecryptVerifyMessageArmored(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		armored,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestAttachmentEncryptionVerification(t *testing.T) {
	var attachment = []byte("Secret file\r\nRoot password:hunter2")

	keyPacket, dataPacket, signature, err := EncryptSignAttachment(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		"password.txt",
		attachment,
	)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	sig := crypto.NewPGPSignature(signature)
	armoredSig, err := sig.GetArmored()
	if err != nil {
		t.Fatal("Expected no error when armoring signature, got:", err)
	}

	_, err = DecryptVerifyAttachment(
		readTestFile("mime_publicKey", false), // Wrong public key
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		keyPacket,
		dataPacket,
		armoredSig,
	)
	assert.EqualError(t, err, "gopenpgp: unable to verify attachment")

	decrypted, err := DecryptVerifyAttachment(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		keyPacket,
		dataPacket,
		armoredSig,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, attachment, decrypted)
}
