package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/stretchr/testify/assert"
)

var testSessionKey *SessionKey

func init() {
	var err error
	testSessionKey, err = GenerateSessionKeyAlgo("aes256")
	if err != nil {
		panic("Expected no error while generating random session key with aes256, got:" + err.Error())
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
	encHandle, _ := testPGP.Encryption().Recipients(keyRingTestPublic).New()
	keyPacket, err := encHandle.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	// Password defined in keyring_test
	decHandle, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	outputSymmetricKey, err := decHandle.DecryptSessionKey(keyPacket)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, testSessionKey, outputSymmetricKey)
}

func TestMultipleAsymmetricKeyPacket(t *testing.T) {
	encHandle, _ := testPGP.Encryption().Recipients(keyRingTestMultiple).New()
	keyPacket, err := encHandle.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	// Password defined in keyring_test
	decHandle, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	outputSymmetricKey, err := decHandle.DecryptSessionKey(keyPacket)
	if err != nil {
		t.Fatal("Expected no error while decrypting key packet, got:", err)
	}

	assert.Exactly(t, testSessionKey, outputSymmetricKey)
}

func TestSymmetricKeyPacket(t *testing.T) {
	password := []byte("I like encryption")

	encHandle, _ := testPGP.Encryption().Password(password).New()
	keyPacket, err := encHandle.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Expected no error while generating key packet, got:", err)
	}

	decHandle, _ := testPGP.Decryption().Password([]byte("Wrong password")).New()
	wrongSymmetricKey, err := decHandle.DecryptSessionKey(keyPacket)
	if err != nil {
		assert.EqualError(t, err, "gopenpgp: unable to decrypt any packet")
	} else {
		assert.NotEqual(t, testSessionKey, wrongSymmetricKey)
	}

	decHandle, _ = testPGP.Decryption().Password(password).New()
	outputSymmetricKey, err := decHandle.DecryptSessionKey(keyPacket)
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

	_, err = encryptSessionKeyWithPassword(sk, password, testPGP.profile.EncryptionConfig())
	if err == nil {
		t.Fatal("Expected error while generating key packet with wrong sized key")
	}
}

func TestDataPacketEncryption(t *testing.T) {
	var message = []byte(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	// Encrypt data with session key
	encryptor, _ := testPGP.Encryption().SessionKey(testSessionKey).New()
	pgpMessage, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Len(t, pgpMessage.Bytes(), 133) // Assert uncompressed encrypted body length

	// Decrypt data with wrong session key
	wrongKey := &SessionKey{
		Key:  []byte("wrong pass"),
		Algo: constants.AES256,
	}
	decryptor, _ := testPGP.Decryption().SessionKey(wrongKey).New()
	_, err = decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	assert.NotNil(t, err)

	// Decrypt data with the good session key
	decryptor, _ = testPGP.Decryption().SessionKey(testSessionKey).New()
	decrypted, err := decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Bytes())

	// Encrypt session key
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))
	encryptor, _ = testPGP.Encryption().Recipients(keyRingTestMultiple).New()
	keyPackets, err := encryptor.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Unable to encrypt key packet, got:", err)
	}

	// Join key packet and data packet in single message
	pgpMessage.KeyPacket = keyPackets

	// Armor and un-armor message. In alternative it can also be done with NewPgpMessage(splitMessage.GetBinary())
	armored, err := pgpMessage.Armor()
	if err != nil {
		t.Fatal("Unable to armor split message, got:", err)
	}

	pgpMessage, err = NewPGPMessageFromArmored(armored)
	if err != nil {
		t.Fatal("Unable to unarmor pgp message, got:", err)
	}
	ids, ok := pgpMessage.EncryptionKeyIDs()
	assert.True(t, ok)
	assert.Exactly(t, 3, len(ids))

	// Test if final decryption succeeds
	decryptor, _ = testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	finalMessageResult, err := decryptor.Decrypt(pgpMessage.Bytes(), Bytes)
	if err != nil {
		t.Fatal("Unable to decrypt joined keypacket and datapacket, got:", err)
	}

	assert.Exactly(t, message, finalMessageResult.Bytes())
}

func TestSessionKeyClear(t *testing.T) {
	testSessionKey.Clear()
	assertMemCleared(t, testSessionKey.Key)
}

func TestAEADDataPacketDecryption(t *testing.T) {
	pgpMessageData, err := os.ReadFile("testdata/gpg2.3-aead-pgp-message.pgp")
	if err != nil {
		t.Fatal("Expected no error when reading message data, got:", err)
	}
	pgpMessage := NewPGPMessage(pgpMessageData)

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
	decryptor, _ := testPGP.Decryption().DecryptionKeys(kR).New()
	sessionKey, err := decryptor.DecryptSessionKey(pgpMessage.BinaryKeyPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting session key, got:", err)
	}

	decryptor, _ = testPGP.Decryption().SessionKey(sessionKey).New()
	decrypted, err := decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, "hello world\n", string(decrypted.Bytes()))
}

func TestDataPacketEncryptionAndSignature(t *testing.T) {
	var message = []byte(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	// Encrypt data with session key
	encryptor, _ := testPGP.Encryption().SessionKey(testSessionKey).SigningKeys(keyRingTestPrivate).New()
	pgpMessage, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting and signing, got:", err)
	}

	// Decrypt data with wrong session key
	wrongKey := &SessionKey{
		Key:  []byte("wrong pass"),
		Algo: constants.AES256,
	}
	decryptor, _ := testPGP.Decryption().SessionKey(wrongKey).New()
	_, err = decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	assert.NotNil(t, err)

	// Decrypt data with the good session key
	decryptor, _ = testPGP.Decryption().SessionKey(testSessionKey).New()
	decrypted, err := decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Bytes())

	// Decrypt & verify data with the good session key but bad keyring
	ecKeyRing, err := NewKeyRing(keyTestEC)
	if err != nil {
		t.Fatal("Unable to generate EC keyring, got:", err)
	}

	decryptor, _ = testPGP.Decryption().SessionKey(testSessionKey).VerificationKeys(ecKeyRing).New()
	decrypted, err = decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	if err != nil {
		t.Fatal("Wrong error returned for verification failure", err)
	}
	if err = decrypted.SignatureError(); err == nil {
		t.Fatal("No error returned for verification failure", err)
	}

	// Decrypt & verify data with the good session key and keyring
	decryptor, _ = testPGP.Decryption().SessionKey(testSessionKey).VerificationKeys(keyRingTestPublic).New()
	decrypted, err = decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting & verifying, got:", err)
	}
	if err = decrypted.SignatureError(); err != nil {
		t.Fatal("Expected no error when decrypting & verifying, got:", err)
	}
	assert.Exactly(t, message, decrypted.Bytes())

	// Encrypt session key
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))
	encryptor, _ = testPGP.Encryption().Recipients(keyRingTestMultiple).New()
	keyPacket, err := encryptor.EncryptSessionKey(testSessionKey)
	if err != nil {
		t.Fatal("Unable to encrypt key packet, got:", err)
	}

	// Join key packet and data packet in single message
	pgpMessage.KeyPacket = keyPacket

	// Armor and un-armor message. In alternative it can also be done with NewPgpMessage(splitMessage.GetBinary())
	armored, err := pgpMessage.Armor()
	if err != nil {
		t.Fatal("Unable to armor split message, got:", err)
	}

	pgpMessage, err = NewPGPMessageFromArmored(armored)
	if err != nil {
		t.Fatal("Unable to unarmor pgp message, got:", err)
	}
	ids, ok := pgpMessage.EncryptionKeyIDs()
	assert.True(t, ok)
	assert.Exactly(t, 3, len(ids))

	// Test if final decryption & verification succeeds
	decryptor, _ = testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).VerificationKeys(keyRingTestPublic).New()
	finalMessage, err := decryptor.Decrypt(pgpMessage.Bytes(), Bytes)
	if err != nil {
		t.Fatal("Unable to decrypt and verify joined keypacket and datapacket, got:", err)
	}
	if err = finalMessage.SignatureError(); err != nil {
		t.Fatal("Unexpected verification error for joined keypacket and datapacket, got:", err)
	}

	assert.Exactly(t, message, finalMessage.Bytes())
}

func TestDataPacketDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}
	decryptor, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	sessionKey, err := decryptor.DecryptSessionKey(pgpMessage.BinaryKeyPacket())
	if err != nil {
		t.Fatal("Expected no error when decrypting session key, got:", err)
	}

	decryptor, _ = testPGP.Decryption().SessionKey(sessionKey).New()
	decrypted, err := decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, readTestFile("message_plaintext", true), string(decrypted.Bytes()))
}

func TestMDCFailDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_badmdc", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	sk, _ := hex.DecodeString("F76D3236E4F8A38785C50BDE7167475E95360BCE67A952710F6C16F18BB0655E")

	sessionKey := NewSessionKeyFromToken(sk, "aes256")

	decryptor, _ := testPGP.Decryption().SessionKey(sessionKey).New()
	_, err = decryptor.Decrypt(pgpMessage.BinaryDataPacket(), Bytes)
	assert.NotNil(t, err)
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

	decryptor, _ := testPGP.Decryption().DecryptionKeys(ukr).New()
	_, err = decryptor.DecryptSessionKey(keyPacket)
	assert.Error(t, err, "gopenpgp: unable to decrypt session key")
}

func TestSessionKeyAeadHandling(t *testing.T) {
	pgp := PGPWithProfile(profile.Default())
	profileAead := profile.Default()
	profileAead.AeadEncryption = &packet.AEADConfig{}
	pgpAead := PGPWithProfile(profileAead)

	keyDefault, err := pgp.KeyGeneration().AddUserId("nodeKey", "nodeKey").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	keyAEAD, err := pgpAead.KeyGeneration().AddUserId("nodeKey", "nodeKey").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	encHandle, _ := pgpAead.Encryption().Recipient(keyDefault).New()
	encHandleAead, _ := pgpAead.Encryption().Recipient(keyAEAD).New()

	sessionKey, err := encHandle.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	sessionKeyAead, err := encHandleAead.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}

	if sessionKey.IsV6() {
		t.Error("Expected session key to be non-v6 compatible")
	}
	if !sessionKeyAead.IsV6() {
		t.Error("Expected session key to be v6 compatible")
	}

	pkeskv3, err := encHandle.EncryptSessionKey(sessionKey)
	if err != nil {
		t.Fatal(err)
	}

	pkeskv6, err := encHandle.EncryptSessionKey(sessionKeyAead)
	if err != nil {
		t.Fatal(err)
	}

	checkPKESK(t, pkeskv3, 3)
	checkPKESK(t, pkeskv6, 6)

	encHandle, _ = pgpAead.Encryption().SessionKey(sessionKey).New()
	encHandleAead, _ = pgpAead.Encryption().SessionKey(sessionKeyAead).New()

	seipdv1, err := encHandle.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	seipdv2, err := encHandleAead.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	checkSEIPD(t, seipdv1.DataPacket, 1)
	checkSEIPD(t, seipdv2.DataPacket, 2)
}

func checkPKESK(t *testing.T, data []byte, version int) {
	packets := packet.NewReader(bytes.NewReader(data))
	p, err := packets.Next()
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := p.(*packet.EncryptedKey)
	if !ok {
		t.Fatal("Expected PKESK packet")
	}

	if pk.Version != version {
		t.Errorf("Expected PKESK version %d, got %d", version, pk.Version)
	}
}

func checkSEIPD(t *testing.T, data []byte, version int) {
	packets := packet.NewReader(bytes.NewReader(data))
	p, err := packets.Next()
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := p.(*packet.SymmetricallyEncrypted)
	if !ok {
		t.Fatal("Expected SEIPD packet")
	}

	if pk.Version != version {
		t.Errorf("Expected SEIPD version %d, got %d", version, pk.Version)
	}
}
