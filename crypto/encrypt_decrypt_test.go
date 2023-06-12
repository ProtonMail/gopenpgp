package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/stretchr/testify/assert"
)

const testMessageString = "Hello World!"
const testMessageUTF8 = "Hell\ro World!\nmore\neven more\n"
const testContext = "test-context"

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
	return &testMaterial{
		profileName:        profile.Name,
		pgp:                handle,
		keyRingTestPublic:  keyRingTestPublic,
		keyRingTestPrivate: keyRingTestPrivate,
		testSessionKey:     testSessionKey,
	}
}

func initEncDecTest() {
	for _, profile := range testProfiles {
		material := generateTestKeyMaterial(profile)
		testMaterialForProfiles = append(testMaterialForProfiles, material)
	}
}

type testMaterial struct {
	profileName        string
	pgp                *PGPHandle
	keyRingTestPublic  *KeyRing
	keyRingTestPrivate *KeyRing
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
				true,
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
				true,
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
				true,
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
				true,
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
			decResult, err := decHandle.Decrypt(pgpMessage.GetBinary())
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
			decResult, err = decHandle.Decrypt(pgpMessage.GetBinary())
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
				true,
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
				true,
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
				true,
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
				Armor().
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
				true,
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
				SigningKeys(material.keyRingTestPrivate).
				UTF8().
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
				true,
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
	messageReader, err := decHandle.DecryptingReader(pgpMessageDataReader)
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
				true,
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
				true,
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
				true,
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
				true,
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
				true,
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
				true,
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
				true,
			)
		})
	}
}

func TestPasswordEncryptDecryptDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			password := []byte("password")
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				SigningKeys(material.keyRingTestPrivate).
				DetachedSignature().
				New()
			decHandle, _ := material.pgp.Decryption().
				Password(password).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptSplitDecryptStream(
				t,
				[]byte(testMessageString),
				nil,
				encHandle,
				decHandle,
				splitWriterDetachedSignature,
				true,
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
				true,
			)
		})
	}
}

func TestPasswordEncryptDecryptStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			password := "password"
			encHandle, _ := material.pgp.Encryption().
				Password([]byte(password)).
				New()
			decHandle, _ := material.pgp.Decryption().
				Password([]byte(password)).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				nil,
				encHandle,
				decHandle,
				false,
			)
		})
	}
}

func TestPasswordEncryptSignDecryptStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			password := "password"
			encHandle, _ := material.pgp.Encryption().
				Password([]byte(password)).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				Password([]byte(password)).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testEncryptDecryptStream(
				t,
				[]byte(testMessageUTF8),
				nil,
				encHandle,
				decHandle,
				false,
			)
		})
	}
}

func TestPasswordEncryptSignDecryptStreamWithCachedSession(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			password := "password"
			encHandle, _ := material.pgp.Encryption().
				Password([]byte(password)).
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
				false,
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
				UTF8().
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
			password := []byte("password")
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
	ciphertextBytes := pgpMessage.GetBinary()
	decryptionResult, err := decHandle.Decrypt(ciphertextBytes)
	if err != nil {
		t.Fatal("Expected no error while calling decrypt with key ring, got:", err)
	}
	if err = decryptionResult.SignatureError(); err != nil {
		t.Fatal("Expected no signature verification error, got:", err)
	}
	if !bytes.Equal(decryptionResult.Result(), messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptionResult.Result()), string(messageBytes))
	}
	decryptedMeta := decryptionResult.GetMetadata()
	if expectedMetadata == nil {
		expectedMetadata = &LiteralMetadata{
			filename: metadata.GetFilename(),
			isUTF8:   metadata.GetIsUtf8(),
			ModTime:  metadata.GetTime(),
		}
	}
	if !reflect.DeepEqual(expectedMetadata, decryptedMeta) {
		t.Fatalf("Expected the decrypted metadata to be %v got %v", metadata, decryptedMeta)
	}
}

func testEncryptSplitDecryptStream(
	t *testing.T,
	messageBytes []byte,
	metadata *LiteralMetadata,
	encHandle PGPEncryption,
	decHandle PGPDecryption,
	multiWriterCreator func(Writer, Writer, Writer) PGPSplitWriter,
	checkSig bool,
) {
	messageReader := bytes.NewReader(messageBytes)
	var keyPackets bytes.Buffer
	var ciphertextBuf bytes.Buffer
	var detachedSignature bytes.Buffer
	expectedMetadata := metadata
	splitOutput := multiWriterCreator(&keyPackets, &ciphertextBuf, &detachedSignature)
	messageWriter, err := encHandle.EncryptingWriter(splitOutput)
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
	decryptedReader, err := decHandle.DecryptingReader(pgpMessageReader)
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	_, err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected verify error not read all, got nil")
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	if checkSig {
		verifyResult, err := decryptedReader.VerifySignature()
		if err != nil {
			t.Fatal("Expected no error, got:", err)
		}
		if err = verifyResult.SignatureError(); err != nil {
			t.Fatal("Expected no error while verifying the signature, got:", err)
		}
	}
	decryptedMeta := decryptedReader.GetMetadata()
	if expectedMetadata == nil {
		expectedMetadata = &LiteralMetadata{
			filename: metadata.GetFilename(),
			isUTF8:   metadata.GetIsUtf8(),
			ModTime:  metadata.GetTime(),
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
	checkSig bool,
) {
	messageReader := bytes.NewReader(messageBytes)
	var ciphertextBuf bytes.Buffer
	expectedMetadata := metadata
	messageWriter, err := encHandle.EncryptingWriter(&ciphertextBuf)
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
	decryptedReader, err := decHandle.DecryptingReader(bytes.NewReader(ciphertextBytes))
	if err != nil {
		t.Fatal("Expected no error while calling decrypting stream with key ring, got:", err)
	}
	_, err = decryptedReader.VerifySignature()
	if err == nil {
		t.Fatal("Expected an error while verifying the signature before reading the data, got nil")
	}
	decryptedBytes, err := ioutil.ReadAll(decryptedReader)
	if err != nil {
		t.Fatal("Expected no error while reading the decrypted data, got:", err)
	}
	if !bytes.Equal(decryptedBytes, messageBytes) {
		t.Fatalf("Expected the decrypted data to be %s got %s", string(decryptedBytes), string(messageBytes))
	}
	if checkSig {
		verifyResult, err := decryptedReader.VerifySignature()
		if err != nil {
			t.Fatal("Expected no error while verifying the signature, got:", err)
		}
		if err = verifyResult.SignatureError(); err != nil {
			t.Fatal("Expected no signature error while verifying the signature, got:", err)
		}
	}
	decryptedMeta := decryptedReader.GetMetadata()
	if expectedMetadata == nil {
		expectedMetadata = &LiteralMetadata{
			filename: metadata.GetFilename(),
			isUTF8:   metadata.GetIsUtf8(),
			ModTime:  metadata.GetTime(),
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
