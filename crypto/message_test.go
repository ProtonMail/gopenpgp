package crypto

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp/packet"
)

func TestTextMessageEncryptionWithPassword(t *testing.T) {
	var message = NewPlainMessageFromString("The secret code is... 1, 2, 3, 4, 5")

	// Encrypt data with password
	encrypted, err := EncryptMessageWithPassword(message, testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = DecryptMessageWithPassword(encrypted, []byte("Wrong password"))
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decrypted, err := DecryptMessageWithPassword(encrypted, testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestBinaryMessageEncryptionWithPassword(t *testing.T) {
	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = NewPlainMessage(binData)

	// Encrypt data with password
	encrypted, err := EncryptMessageWithPassword(message, testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	_, err = DecryptMessageWithPassword(encrypted, []byte("Wrong password"))
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decrypted, err := DecryptMessageWithPassword(encrypted, testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted)
}

func TestTextMessageEncryption(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")

	ciphertext, err := keyRingTestPublic.Encrypt(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, keyRingTestPublic, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestBinaryMessageEncryption(t *testing.T) {
	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = NewPlainMessage(binData)

	ciphertext, err := keyRingTestPublic.Encrypt(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, keyRingTestPublic, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetBinary(), decrypted.GetBinary())

	// Decrypt without verifying
	decrypted, err = keyRingTestPrivate.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestIssue11(t *testing.T) {
	var issue11Password = []byte("1234")

	issue11Key, err := NewKeyFromArmored(readTestFile("issue11_privatekey", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}

	issue11Key, err = issue11Key.Unlock(issue11Password)
	if err != nil {
		t.Fatal("Expected no error while unlocking private key, got:", err)
	}

	issue11Keyring, err := NewKeyRing(issue11Key)
	if err != nil {
		t.Fatal("Expected no error while bulding private keyring, got:", err)
	}

	senderKey, err := NewKeyFromArmored(readTestFile("issue11_publickey", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring public keyring, got:", err)
	}
	assert.Exactly(t, "0x643b3595e6ee4fdf", senderKey.GetID())

	senderKeyring, err := NewKeyRing(senderKey)
	if err != nil {
		t.Fatal("Expected no error while building public keyring, got:", err)
	}

	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("issue11_message", false))
	if err != nil {
		t.Fatal("Expected no error while unlocking private keyring, got:", err)
	}

	plainMessage, err := issue11Keyring.Decrypt(pgpMessage, senderKeyring, 0)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "message from sender", plainMessage.GetString())
}

func TestSignedMessageDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, readTestFile("message_plaintext", true), decrypted.GetString())
}

func TestMultipleKeyMessageEncryption(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))

	ciphertext, err := keyRingTestMultiple.Encrypt(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	numKeyPackets := 0
	packets := packet.NewReader(bytes.NewReader(ciphertext.Data))
	for {
		var p packet.Packet
		if p, err = packets.Next(); err == io.EOF {
			break
		}
		if _, ok := p.(*packet.EncryptedKey); ok {
			numKeyPackets++
		}
	}
	assert.Exactly(t, 3, numKeyPackets)

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, keyRingTestPublic, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}
