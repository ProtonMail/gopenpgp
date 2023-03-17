package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/profile"

	"github.com/stretchr/testify/assert"
)

func TestSymmetricKeys(t *testing.T) {
	symmetricKey, err := NewKeyFromArmored(readTestFile("key_symmetric", false))
	if err != nil {
		t.Fatal("Expected no error while unarmoring private keyring, got:", err)
	}
	assert.Exactly(t, packet.PubKeyAlgoAEAD, symmetricKey.entity.PrimaryKey.PubKeyAlgo)
	assert.NotNil(t, symmetricKey.entity.PSK)

	symmetricKeyRing, err := NewKeyRing(symmetricKey)
	if err != nil {
		t.Fatal("Expected no error while building private keyring, got:", err)
	}

	binData, _ := base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")
	pgp := PGP()
	encryptor, err := pgp.Encryption().
		Recipients(symmetricKeyRing).
		SigningKeys(symmetricKeyRing).
		New()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encryptor.Encrypt(binData)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	decryptor, err := pgp.Decryption().
		DecryptionKeys(symmetricKeyRing).
		VerificationKeys(symmetricKeyRing).
		New()
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptor.Decrypt(ciphertext.Bytes(), Bytes)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}
	assert.Exactly(t, binData, decrypted.Bytes())
	if sigErr := decrypted.SignatureError(); sigErr != nil {
		t.Fatal("Expected no signature error, got:", sigErr)
	}
}

func TestGenerateSymmetricKey(t *testing.T) {
	assertSymmetric := func(t *testing.T, key *Key) {
		assert.Exactly(t, packet.PubKeyAlgoAEAD, key.entity.PrimaryKey.PubKeyAlgo)
		assert.NotNil(t, key.entity.PSK)
		assert.True(t, key.IsPrivate())
		assert.False(t, key.IsExpired(testTime))
	}

	t.Run("Profile", func(t *testing.T) {
		key, err := PGPWithProfile(profile.Symmetric()).KeyGeneration().New().GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		assertSymmetric(t, key)
	})

	t.Run("Override", func(t *testing.T) {
		key, err := PGP().KeyGeneration().
			OverrideProfileAlgorithm(KeyGenerationSymmetric).
			New().
			GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		assertSymmetric(t, key)
	})

	t.Run("UserIdNotSupported", func(t *testing.T) {
		_, err := PGPWithProfile(profile.Symmetric()).KeyGeneration().
			AddUserId("test", "test@test.test").
			New().
			GenerateKey()
		assert.Error(t, err)
	})

	t.Run("LifetimeNotSupported", func(t *testing.T) {
		_, err := PGPWithProfile(profile.Symmetric()).KeyGeneration().
			Lifetime(3600).
			New().
			GenerateKey()
		assert.Error(t, err)
	})
}
