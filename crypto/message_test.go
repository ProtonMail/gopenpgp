package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
)

func TestTextMessageEncryptionWithPassword(t *testing.T) {
	var message = NewPlainMessageFromString("The secret code is... 1, 2, 3, 4, 5")

	// Encrypt data with password
	encrypted, err := EncryptMessageWithPassword(message, testSymmetricKey)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	packets := packet.NewReader(bytes.NewReader(encrypted.GetBinary()))
	var foundSk bool
	for {
		var p packet.Packet
		var errEOF error
		if p, errEOF = packets.Next(); errors.Is(errEOF, io.EOF) {
			break
		}
		sessionKey, ok := p.(*packet.SymmetricKeyEncrypted)
		if ok {
			assert.Equal(t, sessionKey.CipherFunc, packet.CipherAES256)
			foundSk = true
			break
		}
	}
	if !foundSk {
		t.Fatal("Expect to found encrypted session key")
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

func TestTextMixedMessageDecryptionWithPassword(t *testing.T) {
	encrypted, err := NewPGPMessageFromArmored(readTestFile("message_mixedPasswordPublic", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	// Decrypt data with the good password
	decrypted, err := DecryptMessageWithPassword(encrypted, []byte("pinata"))
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	expected, err := os.ReadFile("testdata/message_mixedPasswordPublicExpected")
	if err != nil {
		panic(err)
	}

	assert.Exactly(t, expected, decrypted.GetBinary())
}

func TestTextMessageEncryption(t *testing.T) {
	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	ciphertext, err := keyRingTestPublic.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	split, err := ciphertext.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	assert.Len(t, split.GetBinaryDataPacket(), 133) // Assert uncompressed encrypted body length

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestTextMessageEncryptionWithTrailingSpaces(t *testing.T) {
	var original = "The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5    "
	var message = NewPlainMessageFromString(original)

	ciphertext, err := keyRingTestPublic.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, original, decrypted.GetString())
}

func TestTextMessageEncryptionWithNonCanonicalLinebreak(t *testing.T) {
	var original = "The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5   \n   \n"
	var message = NewPlainMessageFromString(original)

	ciphertext, err := keyRingTestPublic.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, original, decrypted.GetString())
}

func TestTextMessageEncryptionWithCompression(t *testing.T) {
	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	ciphertext, err := keyRingTestPublic.EncryptWithCompression(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	split, err := ciphertext.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	assert.Len(t, split.GetBinaryDataPacket(), 117) // Assert uncompressed encrypted body length

	decrypted, err := keyRingTestPrivate.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
}

func TestTextMessageEncryptionWithSignature(t *testing.T) {
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
	pgp.latestServerTime = 1559655272
	defer func() {
		pgp.latestServerTime = testTime
	}()

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
		t.Fatal("Expected no error while building private keyring, got:", err)
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
		t.Fatal("Expected no error while reading ciphertext, got:", err)
	}

	plainMessage, err := issue11Keyring.Decrypt(pgpMessage, senderKeyring, 0)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "message from sender", plainMessage.GetString())
}

func TestDummy(t *testing.T) {
	pgp.latestServerTime = 1636644417
	defer func() { pgp.latestServerTime = testTime }()

	dummyKey, err := NewKeyFromArmored(readTestFile("key_dummy", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring public keyring, got:", err)
	}

	unlockedDummyKey, err := dummyKey.Unlock([]byte("golang"))
	if err != nil {
		t.Fatal("Expected no error while unlocking private key, got:", err)
	}

	_, err = unlockedDummyKey.Lock([]byte("golang"))
	if err != nil {
		t.Fatal("Expected no error while unlocking private key, got:", err)
	}

	dummyKeyRing, err := NewKeyRing(unlockedDummyKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	var message = NewPlainMessageFromString(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	ciphertext, err := dummyKeyRing.Encrypt(message, nil)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	split, err := ciphertext.SplitMessage()
	if err != nil {
		t.Fatal("Expected no error when splitting, got:", err)
	}

	assert.Len(t, split.GetBinaryDataPacket(), 133) // Assert uncompressed encrypted body length

	decrypted, err := dummyKeyRing.Decrypt(ciphertext, nil, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message.GetString(), decrypted.GetString())
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

func TestSHA256SignedMessageDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_sha256_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(pgpMessage, keyRingTestPrivate, 0)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, readTestFile("message_plaintext", true), decrypted.GetString())
}

func TestSHA1SignedMessageDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_sha1_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decrypted, err := keyRingTestPrivate.Decrypt(pgpMessage, keyRingTestPrivate, 0)
	if err == nil {
		t.Fatal("Expected verification error when decrypting")
	}
	if err.Error() != "Signature Verification Error: Insecure signature" {
		t.Fatal("Expected verification error when decrypting, got:", err)
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

func TestMessageGetEncryptionKeyIDs(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))

	ciphertext, err := keyRingTestMultiple.Encrypt(message, keyRingTestPrivate)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	ids, ok := ciphertext.GetEncryptionKeyIDs()
	assert.Exactly(t, 3, len(ids))
	assert.True(t, ok)
	encKey, ok := keyRingTestMultiple.entities[0].EncryptionKey(time.Now())
	assert.True(t, ok)
	assert.Exactly(t, encKey.PublicKey.KeyId, ids[0])
}

func TestMessageGetHexGetEncryptionKeyIDs(t *testing.T) {
	ciphertext, err := NewPGPMessageFromArmored(readTestFile("message_multipleKeyID", false))
	if err != nil {
		t.Fatal("Expected no error when reading message, got:", err)
	}

	ids, ok := ciphertext.GetHexEncryptionKeyIDs()
	assert.Exactly(t, 2, len(ids))
	assert.True(t, ok)

	assert.Exactly(t, "76ad736fa7e0e83c", ids[0])
	assert.Exactly(t, "0f65b7ae456a9ceb", ids[1])
}

func TestMessageGetSignatureKeyIDs(t *testing.T) {
	var message = NewPlainMessageFromString("plain text")

	signature, err := keyRingTestPrivate.SignDetached(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	ids, ok := signature.GetSignatureKeyIDs()
	assert.Exactly(t, 1, len(ids))
	assert.True(t, ok)
	signingKey, ok := keyRingTestPrivate.entities[0].SigningKey(time.Now())
	assert.True(t, ok)
	assert.Exactly(t, signingKey.PublicKey.KeyId, ids[0])
}

func TestMessageGetHexSignatureKeyIDs(t *testing.T) {
	ciphertext, err := NewPGPMessageFromArmored(readTestFile("message_plainSignature", false))
	if err != nil {
		t.Fatal("Expected no error when reading message, got:", err)
	}

	ids, ok := ciphertext.GetHexSignatureKeyIDs()
	assert.Exactly(t, 2, len(ids))
	assert.True(t, ok)

	assert.Exactly(t, "3eb6259edf21df24", ids[0])
	assert.Exactly(t, "d05b722681936ad0", ids[1])
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

func TestPGPSplitMessageFromArmoredWithAEAD(t *testing.T) {
	var message = `-----BEGIN PGP MESSAGE-----

hF4DJDxTg/yg6TkSAQdA3Ogzuxwz7IdSRCh81gdYuB0bKqkYDs7EksOkYJ7eUnMw
FsRNg+X3KbCj9j747An4J7V8trghOIN00dlpuR77wELS79XHoP55qmyVyPzmTXdx
1F8BCQIQyGCAxAA1ppydoBVp7ithTEl2bU72tbOsLCFY8TBamG6t3jfqJpO2lz+G
M0xNgvwIDrAQsN35VGw72I/FvWJ0VG3rpBKgFp5nPK0NblRomXTRRfoNgSoVUcxU
vA==
=YNf2
-----END PGP MESSAGE-----
`
	split, err := NewPGPSplitMessageFromArmored(message)
	if err != nil {
		t.Errorf("Couldn't parse split message: %v", err)
	}
	if split.KeyPacket == nil {
		t.Error("Key packet was nil")
	}
	if split.DataPacket == nil {
		t.Error("Data packet was nil")
	}
}
