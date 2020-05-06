package crypto

import (
	"bytes"
	"encoding/base64"
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
	assert.Exactly(t, "643b3595e6ee4fdf", senderKey.GetHexKeyID())

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

	// Test that ciphertext data contains three Encrypted Key Packets (tag 1)
	// followed by a single symmetrically encrypted data packet (tag 18)
	var p packet.Packet
	packets := packet.NewReader(bytes.NewReader(ciphertext.Data))
	for i := 0; i < 3; i++ {
		if p, err = packets.Next(); err != nil {
			t.Fatal(err.Error())
		}
		if _, ok := p.(*packet.EncryptedKey); !ok {
			t.Fatalf("Expected Encrypted Key packet, got %T", p)
		}
	}
	if p, err = packets.Next(); err != nil {
		t.Fatal(err.Error())
	}
	if _, ok := p.(*packet.SymmetricallyEncrypted); !ok {
		t.Fatalf("Expected Symmetrically Encrypted Data packet, got %T", p)
	}

	// Decrypt message and verify correctness
	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, keyRingTestPublic, GetUnixTime())
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestMessageGetArmoredWithCustomHeaders(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")

	ciphertext, err := keyRingTestPublic.Encrypt(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	comment := "User-defined comment"
	version := "User-defined version"
	armored, err := ciphertext.GetArmoredWithCustomHeaders(comment, version)
	if err != nil {
		t.Fatal("Could not armor the ciphertext:", err)
	}

	assert.Contains(t, armored, "Comment: "+comment)
	assert.Contains(t, armored, "Version: "+version)
}

func TestMessageGetArmoredWithEmptyHeaders(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")

	ciphertext, err := keyRingTestPublic.Encrypt(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	comment := ""
	version := ""
	armored, err := ciphertext.GetArmoredWithCustomHeaders(comment, version)
	if err != nil {
		t.Fatal("Could not armor the ciphertext:", err)
	}

	assert.NotContains(t, armored, "Version")
	assert.NotContains(t, armored, "Comment")
}
