package helper

import (
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEncryptedKeyFieldsFromMessage(t *testing.T) {
	publicKey := readTestFile("keyring_publicKey", false)
	privateKey := readTestFile("keyring_privateKey", false)

	plaintext := "test message for key field extraction"
	armored, err := EncryptMessageArmored(publicKey, plaintext)
	require.NoError(t, err)

	pgpMessage, err := crypto.NewPGPMessageFromArmored(armored)
	require.NoError(t, err)

	keyID, algo, mpi1, mpi2, err := GetEncryptedKeyFieldsFromMessage(pgpMessage)
	require.NoError(t, err)

	assert.NotZero(t, keyID)
	assert.Equal(t, int(packet.PubKeyAlgoRSA), algo)
	assert.NotEmpty(t, mpi1, "MPI1 should not be empty for RSA")
	assert.Nil(t, mpi2, "MPI2 should be nil for RSA")

	// Verify message is still decryptable.
	decrypted, err := DecryptMessageArmored(privateKey, testMailboxPassword, armored)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptMessageWithECDHSharedSecret(t *testing.T) {
	// Generate EdDSA+ECDH key (ed25519 primary + curve25519 ECDH subkey).
	// Use gopenpgp's GenerateKey which properly serializes and creates the key.
	// "x25519" produces EdDSA primary + curve25519 ECDH subkey (algo 18).
	key, err := crypto.GenerateKey("test", "test@test.com", "x25519", 0)
	require.NoError(t, err)

	entity := key.GetEntity()

	// Verify we got a classic ECDH subkey (algorithm 18).
	var ecdhSubkey *openpgp.Subkey
	for i := range entity.Subkeys {
		if entity.Subkeys[i].PublicKey.PubKeyAlgo == packet.PubKeyAlgoECDH {
			ecdhSubkey = &entity.Subkeys[i]
			break
		}
	}
	require.NotNil(t, ecdhSubkey, "should have an ECDH subkey")

	publicKeyArmored, err := key.GetArmoredPublicKey()
	require.NoError(t, err)

	// Encrypt a message to the ECDH key.
	plaintext := "shared secret test message"
	publicKeyRing, err := createPublicKeyRing(publicKeyArmored)
	require.NoError(t, err)

	pgpMessage, err := publicKeyRing.Encrypt(crypto.NewPlainMessageFromString(plaintext), nil)
	require.NoError(t, err)

	// Extract encrypted key fields.
	_, algo, mpi1, wrappedKey, err := GetEncryptedKeyFieldsFromMessage(pgpMessage)
	require.NoError(t, err)
	assert.Equal(t, int(packet.PubKeyAlgoECDH), algo)
	assert.NotEmpty(t, mpi1, "MPI1 (ephemeral point) should not be empty")
	assert.NotEmpty(t, wrappedKey, "MPI2 (wrapped key) should not be empty")

	// Simulate hardware token: compute the ECDH shared secret from the
	// ephemeral point and the private scalar.
	ecdhPriv := ecdhSubkey.PrivateKey.PrivateKey.(*ecdh.PrivateKey)
	ephemeral := ecdhPriv.PublicKey.GetCurve().UnmarshalBytePoint(mpi1)
	sharedSecret, err := ecdhPriv.PublicKey.GetCurve().Decaps(ephemeral, ecdhPriv.D)
	require.NoError(t, err, "computing shared secret should succeed")

	// Decrypt using only the shared secret (no private key needed).
	decrypted, err := DecryptMessageWithECDHSharedSecret(pgpMessage, publicKeyArmored, sharedSecret)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}
