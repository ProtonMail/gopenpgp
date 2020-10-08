package helper

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/stretchr/testify/assert"
)

func TestAESEncryption(t *testing.T) {
	var plaintext = "Symmetric secret"
	var passphrase = []byte("passphrase")

	ciphertext, err := EncryptMessageWithPassword(passphrase, plaintext)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	_, err = DecryptMessageWithPassword([]byte("Wrong passphrase"), ciphertext)
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

	assert.Exactly(t, true, crypto.IsPGPMessage(armored))

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
		readTestFile("keyring_privateKey", false),
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		plaintext,
	)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, crypto.IsPGPMessage(armored))

	_, err = DecryptVerifyMessageArmored(
		readTestFile("mime_privateKey", false), // Wrong public key
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		armored,
	)
	assert.EqualError(t, err, "Signature Verification Error: No matching signature")

	decrypted, err := DecryptVerifyMessageArmored(
		readTestFile("keyring_privateKey", false),
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
		readTestFile("keyring_privateKey", false),
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
		readTestFile("mime_privateKey", false), // Wrong public key
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		keyPacket,
		dataPacket,
		armoredSig,
	)
	assert.EqualError(t, err, "gopenpgp: unable to verify attachment")

	decrypted, err := DecryptVerifyAttachment(
		readTestFile("keyring_privateKey", false),
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

func TestArmoredBinaryMessageEncryption(t *testing.T) {
	plainData := []byte("Secret message")

	armored, err := EncryptBinaryMessageArmored(readTestFile("keyring_privateKey", false), plainData)

	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, crypto.IsPGPMessage(armored))

	decrypted, err := DecryptBinaryMessageArmored(
		readTestFile("keyring_privateKey", false),
		testMailboxPassword, // Password defined in base_test
		armored,
	)

	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plainData, decrypted)
}

func TestEncryptSignArmoredDetached(t *testing.T) {
	plainData := []byte("Secret message")
	privateKeyString := readTestFile("keyring_privateKey", false)
	privateKey, err := crypto.NewKeyFromArmored(privateKeyString)
	if err != nil {
		t.Fatal("Error reading the test private key: ", err)
	}
	publicKeyString, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Error reading the test public key: ", err)
	}
	armoredCiphertext, armoredSignature, err := EncryptSignArmoredDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword, // Password defined in base_test
		plainData,
	)
	if err != nil {
		t.Fatal("Expected no error while encrypting and signing, got:", err)
	}

	decrypted, err := DecryptVerifyArmoredDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword,
		armoredCiphertext,
		armoredSignature,
	)

	if err != nil {
		t.Fatal("Expected no error while decrypting and verifying, got:", err)
	}

	if !bytes.Equal(decrypted, plainData) {
		t.Error("Decrypted is not equal to the plaintext")
	}

	_, modifiedSignature, err := EncryptSignArmoredDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword, // Password defined in base_test
		[]byte("Different message"),
	)

	if err != nil {
		t.Fatal("Expected no error while encrypting and signing, got:", err)
	}

	_, err = DecryptVerifyArmoredDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword,
		armoredCiphertext,
		modifiedSignature,
	)

	if err == nil {
		t.Fatal("Expected an error while decrypting and verifying with a wrong signature")
	}
}

func TestEncryptDecryptAttachmenWithKey(t *testing.T) {
	plainData := []byte("Secret message")
	privateKeyString := readTestFile("keyring_privateKey", false)
	privateKey, err := crypto.NewKeyFromArmored(privateKeyString)
	if err != nil {
		t.Fatal("Error reading the test private key: ", err)
	}
	publicKeyString, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Error reading the test public key: ", err)
	}
	pgpSplitMessage, err := EncryptAttachmentWithKey(
		publicKeyString,
		"test_filename",
		plainData,
	)

	if err != nil {
		t.Fatal("Expected no error while encrypting, got:", err)
	}

	decrypted, err := DecryptAttachmentWithKey(
		privateKeyString,
		testMailboxPassword,
		pgpSplitMessage.KeyPacket,
		pgpSplitMessage.DataPacket,
	)

	if err != nil {
		t.Fatal("Expected no error while decrypting, got:", err)
	}

	if !bytes.Equal(decrypted, plainData) {
		t.Error("Decrypted attachment is not equal to the original attachment")
	}
}

func TestEncryptDecryptSessionKey(t *testing.T) {
	privateKeyString := readTestFile("keyring_privateKey", false)
	privateKey, err := crypto.NewKeyFromArmored(privateKeyString)
	if err != nil {
		t.Fatal("Error reading the test private key: ", err)
	}
	publicKeyString, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Error reading the test public key: ", err)
	}

	sessionKey, err := crypto.GenerateSessionKeyAlgo("aes256")

	if err != nil {
		t.Fatal("Expected no error while generating the session key, got:", err)
	}

	encrypted, err := EncryptSessionKey(publicKeyString, sessionKey)

	if err != nil {
		t.Fatal("Expected no error while encrypting session key, got:", err)
	}

	decryptedSessionKey, err := DecryptSessionKey(
		privateKeyString,
		testMailboxPassword,
		encrypted,
	)

	if err != nil {
		t.Fatal("Expected no error while decrypting session key, got:", err)
	}

	if decryptedSessionKey.GetBase64Key() != sessionKey.GetBase64Key() {
		t.Error("Decrypted session key is not equal to the original session key")
	}
}

func TestEncryptSignBinaryDetached(t *testing.T) {
	plainData := []byte("Secret message")
	privateKeyString := readTestFile("keyring_privateKey", false)
	privateKey, err := crypto.NewKeyFromArmored(privateKeyString)
	if err != nil {
		t.Fatal("Error reading the test private key: ", err)
	}
	publicKeyString, err := privateKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Error reading the test public key: ", err)
	}
	encryptedData, armoredSignature, err := EncryptSignBinaryDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword, // Password defined in base_test
		plainData,
	)
	if err != nil {
		t.Fatal("Expected no error while encrypting and signing, got:", err)
	}

	decrypted, err := DecryptVerifyBinaryDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword,
		encryptedData,
		armoredSignature,
	)

	if err != nil {
		t.Fatal("Expected no error while decrypting and verifying, got:", err)
	}

	if !bytes.Equal(decrypted, plainData) {
		t.Error("Decrypted is not equal to the plaintext")
	}

	_, modifiedSignature, err := EncryptSignBinaryDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword, // Password defined in base_test
		[]byte("Different message"),
	)

	if err != nil {
		t.Fatal("Expected no error while encrypting and signing, got:", err)
	}

	_, err = DecryptVerifyBinaryDetached(
		publicKeyString,
		privateKeyString,
		testMailboxPassword,
		encryptedData,
		modifiedSignature,
	)

	if err == nil {
		t.Fatal("Expected an error while decrypting and verifying with a wrong signature")
	}
}
