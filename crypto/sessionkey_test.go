package crypto

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/stretchr/testify/assert"
)

var testSessionKey *SessionKey

func init() {
	var err error
	testSessionKey, err = GenerateSessionKey()
	if err != nil {
		panic("Expected no error while generating random session key with default algorithm, got:" + err.Error())
	}
}

func TestRandomToken(t *testing.T) {
	token40, err := RandomToken(40)
	if err != nil {
		t.Fatal("Expected no error while generating random token, got:", err)
	}
	assert.Len(t, token40, 40)
}

func TestGenerateSessionKey(t *testing.T) {
	assert.Len(t, testSessionKey.Key, 32)
}

func TestAsymmetricKeyPacket(t *testing.T) {
	keyPacket, err := keyRingTestPublic.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	// Password defined in keyring_test
	outputSymmetricKey, err := keyRingTestPrivate.DecryptSessionKey(keyPacket)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, testSessionKey, outputSymmetricKey)
}

func TestMultipleAsymmetricKeyPacket(t *testing.T) {
	keyPacket, err := keyRingTestMultiple.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	// Password defined in keyring_test
	outputSymmetricKey, err := keyRingTestMultiple.DecryptSessionKey(keyPacket)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, testSessionKey, outputSymmetricKey)
}

func TestSymmetricKeyPacket(t *testing.T) {
	password := []byte("I like encryption")

	keyPacket, err := EncryptSessionKeyWithPassword(testSessionKey, password)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	wrongSymmetricKey, err := DecryptSessionKeyWithPassword(keyPacket, []byte("Wrong password"))
	if err != nil {
		assert.EqualError(t, err, "gopenpgp: unable to decrypt any packet")
	} else {
		assert.NotEqual(t, testSessionKey, wrongSymmetricKey)
	}

	outputSymmetricKey, err := DecryptSessionKeyWithPassword(keyPacket, password)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}
	assert.Exactly(t, testSessionKey, outputSymmetricKey)
}

func TestSymmetricKeyPacketWrongSize(t *testing.T) {
	r, err := RandomToken(symKeyAlgos[constants.AES256].KeySize())
	if err != nil {
		t.Fatal("Expected no error while generating session key, got:", err)
	}

	sk := &SessionKey{
		Key:  r,
		Algo: constants.AES128,
	}

	password := []byte("I like encryption")

	_, err = EncryptSessionKeyWithPassword(sk, password)
	if err == nil {
		t.Fatal("Expected error while generating key packet with wrong sized key")
	}
}

func TestDataPacketEncryption(t *testing.T) {
	var message = NewPlainMessageFromString("The secret code is... 1, 2, 3, 4, 5")

	// Encrypt data with session key
	dataPacket, err := testSessionKey.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong session key
	wrongKey := SessionKey{
		Key:  []byte("wrong pass"),
		Algo: constants.AES256,
	}
	_, err = wrongKey.Decrypt(dataPacket)
	assert.NotNil(t, err)

	// Decrypt data with the good session key
	decrypted, err := testSessionKey.Decrypt(dataPacket)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())

	// Encrypt session key
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))
	keyPacket, err := keyRingTestMultiple.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Unable to encrypt key packet, got:", err)
	}

	// Join key packet and data packet in single message
	splitMessage := NewPGPSplitMessage(keyPacket, dataPacket)

	// Armor and un-armor message. In alternative it can also be done with NewPgpMessage(splitMessage.GetBinary())
	armored, err := splitMessage.GetArmored()
	if err != nil {
		t.Fatal("Unable to armor split message, got:", err)
	}

	pgpMessage, err := NewPGPMessageFromArmored(armored)
	if err != nil {
		t.Fatal("Unable to unarmor pgp message, got:", err)
	}
	ids, ok := pgpMessage.GetEncryptionKeyIDs()
	assert.True(t, ok)
	assert.Exactly(t, 3, len(ids))

	// Test if final decryption succeeds
	finalMessage, err := keyRingTestPrivate.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Unable to decrypt joined keypacket and datapacket, got:", err)
	}

	assert.Exactly(t, message.GetString(), finalMessage.GetString())
}

func TestDataPacketDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	split, err := pgpMessage.SeparateKeyAndData(1024, 0)
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	sessionKey, err := keyRingTestPrivate.DecryptSessionKey(split.GetBinaryKeyPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting session key, got:", err)
	}

	decrypted, err := sessionKey.Decrypt(split.GetBinaryDataPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, readTestFile("message_plaintext", true), decrypted.GetString())
}

func TestSessionKeyClear(t *testing.T) {
	testSessionKey.Clear()
	assertMemCleared(t, testSessionKey.Key)
}
