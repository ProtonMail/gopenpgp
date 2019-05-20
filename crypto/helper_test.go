package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArmoredTextMessageEncryption(t *testing.T) {
	var plaintext = "Secret message"

	armored, err := pgp.EncryptMessageArmoredHelper(readTestFile("keyring_publicKey", false), plaintext)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, pgp.IsPGPMessage(armored))

	decrypted, err := pgp.DecryptMessageArmoredHelper(
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		armored,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestArmoredTextMessageEncryptionVerification(t *testing.T) {
	var plaintext = "Secret message"

	armored, err := pgp.EncryptSignMessageArmoredHelper(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		plaintext,
	)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, pgp.IsPGPMessage(armored))

	_, err = pgp.DecryptVerifyMessageArmoredHelper(
		readTestFile("mime_publicKey", false),		// Wrong public key
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		armored,
	)
	assert.EqualError(t, err, "gopenpgp: unable to verify message")


	decrypted, err := pgp.DecryptVerifyMessageArmoredHelper(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		armored,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestAttachmentEncryptionVerification(t *testing.T) {
	var attachment = []byte("Secret file\r\nRoot password:hunter2")

	keyPacket, dataPacket, signature, err := pgp.EncryptSignAttachmentHelper(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		"password.txt",
		attachment,
	)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	sig := NewPGPSignature(signature)
	armoredSig, err := sig.GetArmored()
	if err != nil {
		t.Fatal("Expected no error when armoring signature, got:", err)
	}

	_, err = pgp.DecryptVerifyAttachmentHelper(
		readTestFile("mime_publicKey", false),		// Wrong public key
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		keyPacket,
		dataPacket,
		armoredSig,
	)
	assert.EqualError(t, err, "gopenpgp: unable to verify attachment")


	decrypted, err := pgp.DecryptVerifyAttachmentHelper(
		readTestFile("keyring_publicKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,		// Password defined in keyring_test
		keyPacket,
		dataPacket,
		armoredSig,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, attachment, decrypted)
}
