package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
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
	outputSymmetricKey, err := keyRingTestPrivate.DecryptSessionKey(keyPacket)
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
	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	// Encrypt data with session key
	dataPacket, err := testSessionKey.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Len(t, dataPacket, 133) // Assert uncompressed encrypted body length

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

func TestDataPacketEncryptionAndSignature(t *testing.T) {
	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	// Encrypt data with session key
	dataPacket, err := testSessionKey.EncryptAndSign(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting and signing, got:", err)
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

	// Decrypt & verify data with the good session key but bad keyring
	ecKeyRing, err := NewKeyRing(keyTestEC)
	if err != nil {
		t.Fatal("Unable to generate EC keyring, got:", err)
	}

	castedErr := &SignatureVerificationError{}
	_, err = testSessionKey.DecryptAndVerify(dataPacket, ecKeyRing, GetUnixTime())
	if err == nil || !errors.As(err, castedErr) {
		t.Fatal("No error or wrong error returned for verification failure", err)
	}

	// Decrypt & verify data with the good session key and keyring
	decrypted, err = testSessionKey.DecryptAndVerify(dataPacket, keyRingTestPublic, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting & verifying, got:", err)
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

	// Test with bad verification key succeeds
	_, err = keyRingTestPrivate.Decrypt(pgpMessage, ecKeyRing, GetUnixTime())
	if err == nil || !errors.As(err, castedErr) {
		t.Fatal("No error or wrong error returned for verification failure")
	}

	// Test if final decryption & verification succeeds
	finalMessage, err := keyRingTestPrivate.Decrypt(pgpMessage, keyRingTestPublic, GetUnixTime())
	if err != nil {
		t.Fatal("Unable to decrypt and verify joined keypacket and datapacket, got:", err)
	}

	assert.Exactly(t, message.GetString(), finalMessage.GetString())
}

func TestDataPacketEncryptionAndSignatureWithContext(t *testing.T) {
	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)
	var testContext = "test-context"
	// Encrypt data with session key
	dataPacket, err := testSessionKey.EncryptAndSignWithContext(message, keyRingTestPrivate, NewSigningContext(testContext, true))
	if err != nil {
		t.Fatal("Expected no error when encrypting and signing, got:", err)
	}

	// Decrypt & verify data with the good session key and keyring
	decrypted, err := testSessionKey.DecryptAndVerifyWithContext(
		dataPacket,
		keyRingTestPublic,
		GetUnixTime(),
		NewVerificationContext(testContext, true, 0),
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting & verifying, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestDataPacketDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	split, err := pgpMessage.SeparateKeyAndData(1024, 0) // Test passing parameters for backwards compatibility
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

func TestMDCFailDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_badmdc", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	split, err := pgpMessage.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	sk, _ := hex.DecodeString("F76D3236E4F8A38785C50BDE7167475E95360BCE67A952710F6C16F18BB0655E")

	sessionKey := NewSessionKeyFromToken(sk, "aes256")

	_, err = sessionKey.Decrypt(split.GetBinaryDataPacket())
	assert.NotNil(t, err)
}

func TestSessionKeyClear(t *testing.T) {
	testSessionKey.Clear()
	assertMemCleared(t, testSessionKey.Key)
}

func TestDataPacketEncryptionWithCompression(t *testing.T) {
	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	// Encrypt data with session key
	dataPacket, err := testSessionKey.EncryptWithCompression(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Len(t, dataPacket, 117) // Assert compressed encrypted body length

	// Decrypt data with the good session key
	decrypted, err := testSessionKey.Decrypt(dataPacket)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestAsymmetricKeyPacketDecryptionFailure(t *testing.T) {
	passphrase := []byte("passphrase")
	keyPacket, err := base64.StdEncoding.DecodeString(readTestFile("sessionkey_packet", false))
	if err != nil {
		t.Error("Expected no error while decoding key packet, got:" + err.Error())
	}

	pk, err := NewKeyFromArmored(readTestFile("sessionkey_key", false))
	if err != nil {
		t.Error("Expected no error while unarmoring private key, got:" + err.Error())
	}

	uk, err := pk.Unlock(passphrase)
	if err != nil {
		t.Error("Expected no error while unlocking private key, got:" + err.Error())
	}

	defer uk.ClearPrivateParams()

	ukr, err := NewKeyRing(uk)
	if err != nil {
		t.Error("Expected no error while building private keyring, got:" + err.Error())
	}

	_, err = ukr.DecryptSessionKey(keyPacket)
	assert.Error(t, err, "gopenpgp: unable to decrypt session key")
}

func TestAEADDataPacketDecryption(t *testing.T) {
	pgpMessageData, err := os.ReadFile("testdata/gpg2.3-aead-pgp-message.pgp")
	if err != nil {
		t.Fatal("Expected no error when reading message data, got:", err)
	}
	pgpMessage := NewPGPMessage(pgpMessageData)

	split, err := pgpMessage.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	aeadKey, err := NewKeyFromArmored(readTestFile("gpg2.3-aead-test-key.asc", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring key, got:", err)
	}

	aeadKeyUnlocked, err := aeadKey.Unlock([]byte("test"))
	if err != nil {
		t.Fatal("Expected no error when unlocking, got:", err)
	}
	kR, err := NewKeyRing(aeadKeyUnlocked)
	if err != nil {
		t.Fatal("Expected no error when creating the keyring, got:", err)
	}
	defer kR.ClearPrivateParams()
	sessionKey, err := kR.DecryptSessionKey(split.GetBinaryKeyPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting session key, got:", err)
	}

	decrypted, err := sessionKey.Decrypt(split.GetBinaryDataPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, "hello world\n", decrypted.GetString())
}

func TestSEDDecryption(t *testing.T) {
	pgpMessageData, err := os.ReadFile("testdata/sed_message")
	if err != nil {
		t.Fatal("Expected no error when reading message data, got:", err)
	}
	pgpMessage, err := NewPGPMessageFromArmored(string(pgpMessageData))
	if err != nil {
		t.Fatal("Expected no error when creating message, got:", err)
	}

	split, err := pgpMessage.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	privateKey, err := NewKeyFromArmored(readTestFile("sed_key", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring key, got:", err)
	}

	kR, err := NewKeyRing(privateKey)
	if err != nil {
		t.Fatal("Expected no error when creating the keyring, got:", err)
	}
	defer kR.ClearPrivateParams()
	sessionKey, err := kR.DecryptSessionKey(split.GetBinaryKeyPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting session key, got:", err)
	}

	_, err = sessionKey.Decrypt(split.GetBinaryDataPacket())
	if err == nil {
		t.Fatal("sed packets without authentication should not be allowed", err)
	}
}
