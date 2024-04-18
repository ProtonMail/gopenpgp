package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/stretchr/testify/assert"
)

const testMessageString = "Hello World!"
const testMessageUTF8 = "Hell\ro World!\nmore\neven more\n"
const testContext = "test-context"

var password = []byte("password")
var decPasswords = [][]byte{[]byte("wrongPassword"), password}
var testMaterialForProfiles []*testMaterial

func generateTestKeyMaterial(profile *profile.Custom) *testMaterial {
	handle := PGPWithProfile(profile)
	testSessionKey, err := handle.GenerateSessionKey()
	if err != nil {
		panic("Cannot generate session key:" + err.Error())
	}

	keyTest, err := handle.KeyGeneration().
		AddUserId("test", "test@test.test").
		New().
		GenerateKey()
	if err != nil {
		panic("Cannot generate key:" + err.Error())
	}
	keyTestPublic, err := keyTest.ToPublic()
	if err != nil {
		panic("Cannot extract public key:" + err.Error())
	}
	keyRingTestPrivate, err := NewKeyRing(keyTest)
	if err != nil {
		panic("Cannot create keyring:" + err.Error())
	}
	keyRingTestPublic, err := NewKeyRing(keyTestPublic)
	if err != nil {
		panic("Cannot create keyring:" + err.Error())
	}
	keyWrong, err := handle.KeyGeneration().
		AddUserId("testWrong", "testWrong@test.test").
		New().
		GenerateKey()
	if err != nil {
		panic("Cannot generate key:" + err.Error())
	}
	return &testMaterial{
		profileName:        profile.Name,
		pgp:                handle,
		keyRingTestPublic:  keyRingTestPublic,
		keyRingTestPrivate: keyRingTestPrivate,
		testSessionKey:     testSessionKey,
		keyWrong:           keyWrong,
	}
}

func initEncDecTest() {
	for _, profile := range testProfiles {
		material := generateTestKeyMaterial(profile)
		testMaterialForProfiles = append(testMaterialForProfiles, material)
	}
	if len(testMaterialForProfiles) < 2 {
		return
	}
	firstMaterial := testMaterialForProfiles[0]
	lastMaterial := testMaterialForProfiles[len(testMaterialForProfiles)-1]
	// Mixed keys with different profiles
	mixKeyringPriv := &KeyRing{
		entities: openpgp.EntityList{
			firstMaterial.keyRingTestPrivate.entities[0],
			lastMaterial.keyRingTestPrivate.entities[0],
		},
	}
	mixKeyringPub := &KeyRing{
		entities: openpgp.EntityList{
			firstMaterial.keyRingTestPublic.entities[0],
			lastMaterial.keyRingTestPublic.entities[0],
		},
	}
	mixedTestMaterial := &testMaterial{
		profileName:        fmt.Sprintf("mixed(%s)(%s)", firstMaterial.profileName, lastMaterial.profileName),
		pgp:                lastMaterial.pgp,
		keyRingTestPublic:  mixKeyringPub,
		keyRingTestPrivate: mixKeyringPriv,
		testSessionKey:     lastMaterial.testSessionKey,
	}
	testMaterialForProfiles = append(testMaterialForProfiles, mixedTestMaterial)
}

type testMaterial struct {
	profileName        string
	pgp                *PGPHandle
	keyRingTestPublic  *KeyRing
	keyRingTestPrivate *KeyRing
	keyWrong           *Key
	testSessionKey     *SessionKey
}

func TestEncryptDecryptStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptStreamWithContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptStreamWithContextAndCompression(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				Compress().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptStreamWithCachedSession(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SessionKey(material.testSessionKey).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				DisableIntendedRecipients().
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptCachedSessionOnDecrypt(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SessionKey(material.testSessionKey).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				RetrieveSessionKey().
				New()
			pgpMessage, err := encHandle.Encrypt([]byte(testMessageString))
			if err != nil {
				t.Fatal("Expected no error in encryption, got:", err)
			}
			decResult, err := decHandle.Decrypt(pgpMessage.Bytes(), Bytes)
			if err != nil {
				t.Fatal("Expected no error in decryption, got:", decResult)
			}
			if !bytes.Equal(decResult.SessionKey().Key, material.testSessionKey.Key) {
				t.Fatal("Expected the cached session key to be equal")
			}
			if decResult.SessionKey().Algo != material.testSessionKey.Algo {
				t.Fatal("Expected the session key algorithms to be equal")
			}
			decHandle, _ = material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			decResult, err = decHandle.Decrypt(pgpMessage.Bytes(), Bytes)
			if err != nil {
				t.Fatal("Expected no error in decryption, got:", decResult)
			}
			if decResult.SessionKey() != nil {
				t.Fatal("Expected no cached session key")
			}
		})
	}
}

func TestSessionEncryptDecryptStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionEncryptDecryptStreamWithContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionEncryptDecryptStreamWithContextAndCompression(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				Compress().
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptStreamArmored(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Armor,
			)
		})
	}
}

func TestEncryptDecryptSignUTF8Stream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		metadata := &LiteralMetadata{
			isUTF8: true,
		}
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				Utf8().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				metadata,
				encHandle,
				decHandle,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptUTF8Stream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		metadata := &LiteralMetadata{
			isUTF8: true,
		}
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				Utf8().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				Utf8().
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				metadata,
				encHandle,
				decHandle,
				0,
				Bytes,
			)
		})
	}
}

func TestAEADDecryptionStream(t *testing.T) {
	pgpMessageDataReader, err := os.Open("testdata/gpg2.3-aead-pgp-message.pgp")
	if err != nil {
		t.Fatal("Expected no error when reading message data, got:", err)
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

	decHandle, _ := PGP().Decryption().DecryptionKeys(kR).New()
	messageReader, err := decHandle.DecryptingReader(pgpMessageDataReader, Auto)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	plaintext, err := messageReader.ReadAll()
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, "hello world\n", string(plaintext))
}

func TestEncryptDecryptSplitStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriter,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptSplitStreamWithContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriter,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptSplitStreamWithContextAndCompression(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				Compress().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriter,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionEncryptDecryptSplitStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriter,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionEncryptDecryptSplitStreamWithContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriter,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionEncryptDecryptSplitStreamWithContextAndCompression(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				Compress().
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriter,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				DetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestPasswordEncryptDecryptDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				SigningKeys(material.keyRingTestPrivate).
				DetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				Passwords(decPasswords).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionKeyEncryptDecryptDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				DetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestEncryptDecryptPlaintextDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				PlainDetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				PlainDetachedSignature().
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestPasswordEncryptDecryptPlaintextDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				SigningKeys(material.keyRingTestPrivate).
				PlainDetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				Passwords(decPasswords).
				VerificationKeys(material.keyRingTestPublic).
				PlainDetachedSignature().
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestSessionKeyEncryptDecryptPlaintextDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				SigningKeys(material.keyRingTestPrivate).
				PlainDetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				PlainDetachedSignature().
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				len(material.keyRingTestPrivate.entities),
				Bytes,
			)
		})
	}
}

func TestPasswordEncryptDecryptStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				New()
			decHandle, _ := material.pgp.Decryption().
				Passwords(decPasswords).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				nil,
				encHandle,
				decHandle,
				0,
				Bytes,
			)
		})
	}
}

func TestPasswordEncryptSignDecryptStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				Passwords(decPasswords).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				nil,
				encHandle,
				decHandle,
				0,
				Bytes,
			)
		})
	}
}

func TestPasswordEncryptSignDecryptStreamWithCachedSession(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				SigningKeys(material.keyRingTestPrivate).
				SessionKey(material.testSessionKey).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(material.testSessionKey).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				nil,
				encHandle,
				decHandle,
				0,
				Bytes,
			)
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecrypt(
				t,
				[]byte(testMessage),
				nil,
				encHandle,
				decHandle,
			)
		})
	}
}

func TestEncryptDecryptUTF8(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		metadata := &LiteralMetadata{
			isUTF8: true,
		}
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				Utf8().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecrypt(
				t,
				[]byte(testMessageUTF8),
				metadata,
				encHandle,
				decHandle,
			)
		})
	}
}

func TestEncryptDecryptSessionKey(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				New()
			keyPackets, err := encHandle.EncryptSessionKey(material.testSessionKey)
			if err != nil {
				t.Fatal("Expected no error while generating key packet, got:", err)
			}
			decryptedSessionKey, err := decHandle.DecryptSessionKey(keyPackets)
			if err != nil {
				t.Fatal("Expected no error while decrypting key packet, got:", err)
			}
			if decryptedSessionKey.Algo == "" {
				// for v6 algorithm is not encoded in the key
				assert.Exactly(t, material.testSessionKey.Key, decryptedSessionKey.Key)
			} else {
				assert.Exactly(t, material.testSessionKey, decryptedSessionKey)
			}
		})
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			key := material.keyRingTestPrivate.GetKeys()[0]
			keyLocked, err := material.pgp.LockKey(key, password)
			if err != nil {
				t.Fatal("Expected no error while encrypting key, got:", err)
			}
			unlockedKey, err := keyLocked.Unlock(password)
			if err != nil {
				t.Fatal("Expected no error while decrypting key, got:", err)
			}
			reflect.DeepEqual(key, unlockedKey)
		})
	}
}

func TestEncryptCompressionApplied(t *testing.T) {
	const numReplicas = 10
	builder := strings.Builder{}
	for i := 0; i < numReplicas; i++ {
		builder.WriteString(testMessage)
	}
	messageToEncrypt := builder.String()
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandleCompress, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				Compress().
				New()

			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()

			compressedMessage, err := encHandleCompress.Encrypt([]byte(messageToEncrypt))
			if err != nil {
				t.Fatal(err)
			}
			message, err := encHandle.Encrypt([]byte(messageToEncrypt))
			if err != nil {
				t.Fatal(err)
			}
			if len(compressedMessage.DataPacket) >= len(message.DataPacket) {
				t.Fatal("Expected compressed encrypted message to be smaller than the encrypted message")
			}
		})
	}
}

func TestEncryptDecryptPlaintextDetachedArmor(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			var ciphertextBuf bytes.Buffer
			var detachedSignature bytes.Buffer
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				PlainDetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				PlainDetachedSignature().
				New()
			writer := NewPGPSplitWriterDetachedSignature(&ciphertextBuf, &detachedSignature)
			ctWriter, err := encHandle.EncryptingWriter(writer, Armor)
			if err != nil {
				t.Fatal("Expected no error while encrypting message, got:", err)
			}
			if _, err := ctWriter.Write([]byte(testMessage)); err != nil {
				t.Fatal(err)
			}
			if err := ctWriter.Close(); err != nil {
				t.Fatal(err)
			}
			decryptionResult, err := decHandle.DecryptDetached(ciphertextBuf.Bytes(), detachedSignature.Bytes(), Armor)
			if err != nil {
				t.Fatal("Expected no error while decrypting message, got:", err)
			}
			if !bytes.Equal(decryptionResult.data, []byte(testMessage)) {
				t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptionResult.data), testMessage)
			}
			if err := decryptionResult.SignatureError(); err != nil {
				t.Fatal("Expected no signature error")
			}
			decHandleNotPlaintext, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			_, err = decHandleNotPlaintext.DecryptDetached(ciphertextBuf.Bytes(), detachedSignature.Bytes(), Armor)
			if err == nil {
				t.Fatal("Expected that decrypting an non encrypted plaintext signature fails")
			}
		})
	}
}

func TestEncryptArmor(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			isV6 := material.keyRingTestPublic.GetKeys()[0].isVersionSix()
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			pgpMsg, err := encHandle.Encrypt([]byte(testMessageString))
			if err != nil {
				t.Fatal("Expected no error in encryption, got:", err)
			}
			armoredData, err := pgpMsg.Armor()
			if err != nil {
				t.Fatal("Armoring failed, got:", err)
			}
			hasChecksum := containsChecksum(armoredData)
			if isV6 && hasChecksum {
				t.Fatalf("V6 messages should not have a checksum")
			}
		})
	}
}

func containsChecksum(armored string) bool {
	re := regexp.MustCompile(`=([A-Za-z0-9+/]{4})\s*-----END PGP MESSAGE-----`)
	return re.MatchString(armored)
}

func testEncryptDecrypt(
	t *testing.T,
	messageBytes []byte,
	metadata *LiteralMetadata,
	encHandle PGPEncryption,
	decHandle PGPDecryption,
) {
	expectedMetadata := metadata
	pgpMessage, err := encHandle.Encrypt(messageBytes)
	if err != nil {
		t.Fatal("Expected no error while encrypting with key ring, got:", err)
	}
	ciphertextBytes := pgpMessage.Bytes()
	decryptionResult, err := decHandle.Decrypt(ciphertextBytes, Bytes)
	if err != nil {
		t.Fatal("Expected no error while calling decrypt with key ring, got:", err)
	}
	if err = decryptionResult.SignatureError(); err != nil {
		t.Fatal("Expected no signature verification error, got:", err)
	}
	if !bytes.Equal(decryptionResult.Bytes(), messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptionResult.Bytes()), string(messageBytes))
	}
	decryptedMeta := decryptionResult.Metadata()
	if expectedMetadata == nil {
		expectedMetadata = &LiteralMetadata{
			filename: metadata.Filename(),
			isUTF8:   metadata.IsUtf8(),
			ModTime:  metadata.Time(),
		}
	}
	if !reflect.DeepEqual(expectedMetadata, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", metadata, decryptedMeta)
	}
}

func testEncryptSplitDecryptStream(
	t *testing.T,
	messageBytes []byte,
	metadata *LiteralMetadata, //nolint:unparam
	encHandle PGPEncryption,
	decHandle PGPDecryption,
	multiWriterCreator func(Writer, Writer, Writer) PGPSplitWriter,
	numberOfSigsToVerify int,
	encoding int8, //nolint:unparam
) {
	messageReader := bytes.NewReader(messageBytes)
	var keyPackets bytes.Buffer
	var ciphertextBuf bytes.Buffer
	var detachedSignature bytes.Buffer
	expectedMetadata := metadata
	splitOutput := multiWriterCreator(&keyPackets, &ciphertextBuf, &detachedSignature)
	messageWriter, err := encHandle.EncryptingWriter(splitOutput, encoding)
	if err != nil {
		t.Fatal("Expected no error while encrypting stream with key ring, got:", err)
	}
	bufferSize := 2
	buffer := make([]byte, bufferSize)
	_, err = io.CopyBuffer(messageWriter, messageReader, buffer)
	if err != nil {
		t.Fatal("Expected no error while copying data, got:", err)
	}
	err = messageWriter.Close()
	if err != nil {
		t.Fatal("Expected no error while closing plaintext writer, got:", err)
	}
	keyPacketsBytes := keyPackets.Bytes()
	ciphertextBytes := ciphertextBuf.Bytes()
	detachedSignatureBytes := detachedSignature.Bytes()
	pgpMessageReader := io.MultiReader(
		bytes.NewReader(keyPacketsBytes),
		bytes.NewReader(ciphertextBytes),
	)
	if len(detachedSignatureBytes) != 0 {
		detachedSignatureReader := io.MultiReader(
			bytes.NewReader(keyPacketsBytes),
			bytes.NewReader(detachedSignatureBytes),
		)
		pgpMessageReader = NewPGPSplitReader(pgpMessageReader, detachedSignatureReader)
	}
	decryptedReader, err := decHandle.DecryptingReader(pgpMessageReader, encoding)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	_, err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected verify error not read all, got nil")
	}
	decryptedBytes, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	if numberOfSigsToVerify > 0 {
		verifyResult, err := decryptedReader.VerifySignature()
		if err != nil {
			t.Fatal("Expected no error, got:", err)
		}
		if err = verifyResult.SignatureError(); err != nil {
			t.Fatal("Expected no error while verifying the signature, got:", err)
		}
		if len(verifyResult.Signatures) != numberOfSigsToVerify {
			t.Fatalf("Not enough signatures verified, should be %d", numberOfSigsToVerify)
		}
		for _, verifiedSignature := range verifyResult.Signatures {
			if verifiedSignature.SignatureError != nil {
				t.Fatal("One of the contained signatures did not correctly verify ", verifiedSignature.SignatureError.Message)
			}
		}
	}
	decryptedMeta := decryptedReader.GetMetadata()
	if expectedMetadata == nil {
		expectedMetadata = &LiteralMetadata{
			filename: metadata.Filename(),
			isUTF8:   metadata.IsUtf8(),
			ModTime:  metadata.Time(),
		}
	}
	if !reflect.DeepEqual(expectedMetadata, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", metadata, decryptedMeta)
	}
}

func testEncryptDecryptStream(
	t *testing.T,
	messageBytes []byte,
	metadata *LiteralMetadata,
	encHandle PGPEncryption,
	decHandle PGPDecryption,
	numberOfSigsToVerify int,
	encoding int8,
) {
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	expectedMetadata := metadata
	messageWriter, err := encHandle.EncryptingWriter(&ciphertextBuf, encoding)
	if err != nil {
		t.Fatal("Expected no error while encrypting stream with key ring, got:", err)
	}
	bufferSize := 2
	buffer := make([]byte, bufferSize)
	_, err = io.CopyBuffer(messageWriter, messageReader, buffer)
	if err != nil {
		t.Fatal("Expected no error while copying data, got:", err)
	}
	err = messageWriter.Close()
	if err != nil {
		t.Fatal("Expected no error while closing plaintext writer, got:", err)
	}
	ciphertextBytes := ciphertextBuf.Bytes()
	decryptedReader, err := decHandle.DecryptingReader(bytes.NewReader(ciphertextBytes), encoding)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	_, err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature before reading the data, got nil")
	}
	decryptedBytes, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	if numberOfSigsToVerify > 0 {
		verifyResult, err := decryptedReader.VerifySignature()
		if err != nil {
			t.Fatal("Expected no error while verifying the signature, got:", err)
		}
		if err = verifyResult.SignatureError(); err != nil {
			t.Fatal("Expected no signature error while verifying the signature, got:", err)
		}
		if len(verifyResult.Signatures) != numberOfSigsToVerify {
			t.Fatalf("Not enough signatures verified, should be %d", numberOfSigsToVerify)
		}
		for _, verifiedSignature := range verifyResult.Signatures {
			if verifiedSignature.SignatureError != nil {
				t.Fatal("One of the contained signatures did not correctly verify ", verifiedSignature.SignatureError.Message)
			}
		}
	}
	decryptedMeta := decryptedReader.GetMetadata()
	if expectedMetadata == nil {
		expectedMetadata = &LiteralMetadata{
			filename: metadata.Filename(),
			isUTF8:   metadata.IsUtf8(),
			ModTime:  metadata.Time(),
		}
	}
	if !reflect.DeepEqual(expectedMetadata, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", metadata, decryptedMeta)
	}
}

func splitWriter(w1 Writer, w2 Writer, w3 Writer) PGPSplitWriter {
	return NewPGPSplitWriterKeyAndData(w1, w2)
}

func splitWriterDetachedSignature(w1 Writer, w2 Writer, w3 Writer) PGPSplitWriter {
	return NewPGPSplitWriter(w1, w2, w3)
}
