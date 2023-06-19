package crypto

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestTextMessageEncryptionWithPassword(t *testing.T) {
	var message = []byte("The secret code is... 1, 2, 3, 4, 5")

	// Encrypt data with password
	encryptor, _ := testPGP.Encryption().Password(testSymmetricKey).New()
	encrypted, err := encryptor.Encrypt(message)
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
	decryptorWrong, _ := testPGP.Decryption().Password([]byte("Wrong password")).New()
	_, err = decryptorWrong.Decrypt(encrypted.GetBinary(), Bytes)
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decryptor, _ := testPGP.Decryption().Password(testSymmetricKey).New()
	decrypted, err := decryptor.Decrypt(encrypted.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, string(message), string(decrypted.Result()))
}

func TestBinaryMessageEncryptionWithPassword(t *testing.T) {
	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	var message = binData

	// Encrypt data with password
	encryptor, _ := testPGP.Encryption().Password(testSymmetricKey).New()
	encrypted, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	// Decrypt data with wrong password
	decryptorWrong, _ := testPGP.Decryption().Password([]byte("Wrong password")).New()
	_, err = decryptorWrong.Decrypt(encrypted.GetBinary(), Bytes)
	assert.NotNil(t, err)

	// Decrypt data with the good password
	decryptor, _ := testPGP.Decryption().Password(testSymmetricKey).New()
	decrypted, err := decryptor.Decrypt(encrypted.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Result())
}

func TestTextMixedMessageDecryptionWithPassword(t *testing.T) {
	encrypted, err := NewPGPMessageFromArmored(readTestFile("message_mixedPasswordPublic", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	// Decrypt data with the good password
	decryptor, _ := testPGP.Decryption().Password([]byte("pinata")).New()
	decrypted, err := decryptor.Decrypt(encrypted.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	expected, err := ioutil.ReadFile("testdata/message_mixedPasswordPublicExpected")
	if err != nil {
		panic(err)
	}

	assert.Exactly(t, expected, decrypted.Result())
}

func TestTextMessageEncryption(t *testing.T) {
	var message = []byte(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)
	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestPublic).New()
	ciphertext, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Len(t, ciphertext.GetBinaryDataPacket(), 133) // Assert uncompressed encrypted body length

	decryptor, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	decrypted, err := decryptor.Decrypt(ciphertext.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Result())
}

func TestTextMessageEncryptionWithTrailingSpaces(t *testing.T) {
	var original = "The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5    "
	var message = []byte(original)

	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestPublic).New()
	ciphertext, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decryptor, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	decrypted, err := decryptor.Decrypt(ciphertext.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Result())
}

func TestTextMessageEncryptionWithNonCanonicalLinebreak(t *testing.T) {
	var original = "The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5   \n   \n"
	var message = []byte(original)

	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestPublic).New()
	ciphertext, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decryptor, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	decrypted, err := decryptor.Decrypt(ciphertext.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Result())
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
	decryptor, _ := testPGP.Decryption().
		DecryptionKeys(issue11Keyring).
		VerificationKeys(senderKeyring).
		VerifyTime(1559655272).New()
	decrypted, err := decryptor.Decrypt(pgpMessage.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}
	if err = decrypted.SignatureError(); err != nil {
		t.Fatal("Expected no error while decrypting/verifying, got:", err)
	}

	assert.Exactly(t, "message from sender", string(decrypted.Result()))
}

func TestDummy(t *testing.T) {
	dummyKey, err := NewKeyFromArmored(readTestFile("key_dummy", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring public keyring, got:", err)
	}

	unlockedDummyKey, err := dummyKey.Unlock([]byte("golang"))
	if err != nil {
		t.Fatal("Expected no error while unlocking private key, got:", err)
	}

	_, err = testPGP.LockKey(unlockedDummyKey, []byte("golang"))
	if err != nil {
		t.Fatal("Expected no error while unlocking private key, got:", err)
	}

	dummyKeyRing, err := NewKeyRing(unlockedDummyKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	var message = []byte(
		"The secret code is... 1, 2, 3, 4, 5. I repeat: the secret code is... 1, 2, 3, 4, 5",
	)

	encryptor, _ := testPGP.Encryption().SignTime(1636644417).Recipients(dummyKeyRing).New()
	ciphertext, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Len(t, ciphertext.GetBinaryDataPacket(), 133) // Assert uncompressed encrypted body length

	decryptor, _ := testPGP.Decryption().DecryptionKeys(dummyKeyRing).New()
	decrypted, err := decryptor.Decrypt(ciphertext.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Result())
}

func TestSignedMessageDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decryptor, _ := testPGP.Decryption().DecryptionKeys(keyRingTestPrivate).New()
	decrypted, err := decryptor.Decrypt(pgpMessage.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, readTestFile("message_plaintext", true), string(decrypted.Result()))
}

func TestSHA256SignedMessageDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_sha256_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decryptor, _ := testPGP.Decryption().
		DecryptionKeys(keyRingTestPrivate).
		VerificationKeys(keyRingTestPrivate).
		DisableVerifyTimeCheck().
		New()
	decrypted, err := decryptor.Decrypt(pgpMessage.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	if err = decrypted.SignatureError(); err != nil {
		t.Fatal("Expected no signature error when decrypting, got:", err)
	}
	assert.Exactly(t, readTestFile("message_plaintext", true), string(decrypted.Result()))
}

func TestSHA1SignedMessageDecryption(t *testing.T) {
	pgpMessage, err := NewPGPMessageFromArmored(readTestFile("message_sha1_signed", false))
	if err != nil {
		t.Fatal("Expected no error when unarmoring, got:", err)
	}

	decryptor, _ := testPGP.Decryption().
		DecryptionKeys(keyRingTestPrivate).
		VerificationKeys(keyRingTestPrivate).
		DisableVerifyTimeCheck().
		New()
	decrypted, err := decryptor.Decrypt(pgpMessage.GetBinary(), Bytes)
	if err = decrypted.SignatureError(); err == nil {
		t.Fatal("Expected verification error when decrypting")
	}
	if errStr := decrypted.SignatureError().Error(); errStr != "Signature Verification Error: Insecure signature" {
		t.Fatal("Expected verification error when decrypting, got:", errStr)
	}
	assert.Exactly(t, readTestFile("message_plaintext", true), string(decrypted.Result()))
}

func TestMultipleKeyMessageEncryption(t *testing.T) {
	var message = []byte("plain text")
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))

	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestMultiple).SigningKeys(keyRingTestPrivate).New()
	ciphertext, err := encryptor.Encrypt(message)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	// Test that ciphertext data contains three Encrypted Key Packets (tag 1)
	// followed by a single symmetrically encrypted data packet (tag 18)
	var p packet.Packet
	packets := packet.NewReader(bytes.NewReader(ciphertext.GetBinary()))
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
	decryptor, _ := testPGP.Decryption().
		DecryptionKeys(keyRingTestPrivate).
		VerificationKeys(keyRingTestPublic).
		New()
	decrypted, err := decryptor.Decrypt(ciphertext.GetBinary(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	if err = decrypted.SignatureError(); err != nil {
		t.Fatal("Expected no signature error when decrypting, got:", err)
	}
	assert.Exactly(t, message, decrypted.Result())
}

func TestMessageGetEncryptionKeyIDs(t *testing.T) {
	var message = []byte("plain text")
	assert.Exactly(t, 3, len(keyRingTestMultiple.entities))

	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestMultiple).SigningKeys(keyRingTestPrivate).New()
	ciphertext, err := encryptor.Encrypt(message)
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
	var message = []byte("plain text")

	signer, _ := testPGP.Sign().SigningKeys(keyRingTestPrivate).Detached().New()
	signature, err := signer.Sign(message, Bytes)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	ids, ok := SignatureKeyIDs(signature)
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
	var message = []byte("plain text")

	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestPublic).SigningKeys(keyRingTestPrivate).New()
	ciphertext, err := encryptor.Encrypt(message)
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
	var message = []byte("plain text")

	encryptor, _ := testPGP.Encryption().Recipients(keyRingTestPublic).SigningKeys(keyRingTestPrivate).New()
	ciphertext, err := encryptor.Encrypt(message)
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
	msg, err := NewPGPMessageFromArmored(message)
	if err != nil {
		t.Errorf("Couldn't parse split message: %v", err)
	}
	if msg.KeyPacket == nil {
		t.Error("Key packet was nil")
	}
	if msg.DataPacket == nil {
		t.Error("Data packet was nil")
	}
}
