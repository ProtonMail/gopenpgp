package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/stretchr/testify/assert"
)

func TestForwardeeDecryption(t *testing.T) {
	pgp.latestServerTime = 1679044110
	defer func() {
		pgp.latestServerTime = testTime
	}()

	forwardeeKey, err := NewKeyFromArmored(readTestFile("key_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	forwardeeKeyRing, err := NewKeyRing(forwardeeKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_forwardee", false))
	if err != nil {
		t.Fatal("Expected no error while reading ciphertext, got:", err)
	}

	plainMessage, err := forwardeeKeyRing.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "Message for Bob", plainMessage.GetString())
}

func TestSymmetricKeys(t *testing.T) {
	// Persistent symmetric keys are only supported by the go-crypto packet API,
	// since they are not regular OpenPGP entities.
	keyPacket, err := armor.Unarmor(readTestFile("key_symmetric", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring symmetric key, got:", err)
	}

	p, err := packet.Read(bytes.NewReader(keyPacket))
	if err != nil {
		t.Fatal("Expected no error while parsing symmetric key, got:", err)
	}
	psk, ok := p.(*packet.PersistentSymmetricKey)
	if !ok {
		t.Fatalf("Expected a persistent symmetric key packet, got: %T", p)
	}

	sessionKey, err := GenerateSessionKey()
	if err != nil {
		t.Fatal("Expected no error when generating session key, got:", err)
	}
	cipherFunc, err := sessionKey.GetCipherFunc()
	if err != nil {
		t.Fatal("Expected no error when getting cipher function, got:", err)
	}

	var keyPacketBuf bytes.Buffer
	if err := packet.SerializeEncryptedKeyPSK(&keyPacketBuf, psk, cipherFunc, false, sessionKey.Key, nil); err != nil {
		t.Fatal("Expected no error when encrypting session key, got:", err)
	}

	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = NewPlainMessage(binData)

	dataPacket, err := sessionKey.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	p, err = packet.Read(&keyPacketBuf)
	if err != nil {
		t.Fatal("Expected no error while parsing key packet, got:", err)
	}
	encryptedKey, ok := p.(*packet.EncryptedKey)
	if !ok {
		t.Fatalf("Expected an encrypted key packet, got: %T", p)
	}
	if err := encryptedKey.Decrypt(&psk.PrivateKey, nil); err != nil {
		t.Fatal("Expected no error when decrypting session key, got:", err)
	}
	decryptedSessionKey, err := newSessionKeyFromEncrypted(encryptedKey)
	if err != nil {
		t.Fatal("Expected no error when reading session key, got:", err)
	}
	assert.Exactly(t, sessionKey.Key, decryptedSessionKey.Key)

	decrypted, err := decryptedSessionKey.Decrypt(dataPacket)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetBinary(), decrypted.GetBinary())
}
