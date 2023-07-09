package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

const benchmarkMessageSize = 1024 // Signed / encrypted message size in bytes

type keyGenerateData struct {
	Algorithm                       string
	RSABits, SphincsPlusParameterId int
}

var benchmarkTestSet = map[string]keyGenerateData{
	"RSA_1024": {
		Algorithm: "RSA",
		RSABits:   1024,
	},
	"RSA_2048": {
		Algorithm: "RSA",
		RSABits:   2048,
	},
	"RSA_3072": {
		Algorithm: "RSA",
		RSABits:   3072,
	},
	"RSA_4096": {
		Algorithm: "RSA",
		RSABits:   4096,
	},
	"Ed25519_X25519": {
		Algorithm: "Ed25519",
	},
	"Ed448_X448": {
		Algorithm: "Ed448",
	},
	"P256": {
		Algorithm: "P256",
	},
	"P384": {
		Algorithm: "P384",
	},
	"P521": {
		Algorithm: "P521",
	},
	"Brainpool256": {
		Algorithm: "BrainpoolP256",
	},
	"Brainpool384": {
		Algorithm: "BrainpoolP384",
	},
	"Brainpool512": {
		Algorithm: "BrainpoolP512",
	},
	"Dilithium3Ed25519_Kyber768X25519": {
		Algorithm: "Dilithium3Ed25519",
	},
	"Dilithium5Ed448_Kyber1024X448": {
		Algorithm: "Dilithium5Ed448",
	},
	"Dilithium3P256_Kyber768P256": {
		Algorithm: "Dilithium3P256",
	},
	"Dilithium5P384_Kyber1024P384": {
		Algorithm: "Dilithium5P384",
	},
	"Dilithium3Brainpool256_Kyber768Brainpool256": {
		Algorithm: "Dilithium3Brainpool256",
	},
	"Dilithium5Brainpool384_Kyber1024Brainpool384": {
		Algorithm: "Dilithium5Brainpool384",
	},
	"SphincsPlusSHA2_128s_Kyber1024X448": {
		Algorithm:              "SphincsPlusSHA2",
		SphincsPlusParameterId: 1,
	},
	"SphincsPlusSHA2_128f_Kyber1024X448": {
		Algorithm:              "SphincsPlusSHA2",
		SphincsPlusParameterId: 2,
	},
	"SphincsPlusSHA2_192s_Kyber1024X448": {
		Algorithm:              "SphincsPlusSHA2",
		SphincsPlusParameterId: 3,
	},
	"SphincsPlusSHA2_192f_Kyber1024X448": {
		Algorithm:              "SphincsPlusSHA2",
		SphincsPlusParameterId: 4,
	},
	"SphincsPlusSHA2_256s_Kyber1024X448": {
		Algorithm:              "SphincsPlusSHA2",
		SphincsPlusParameterId: 5,
	},
	"SphincsPlusSHA2_256f_Kyber1024X448": {
		Algorithm:              "SphincsPlusSHA2",
		SphincsPlusParameterId: 6,
	},
	"SphincsPlusSHAKE_128s_Kyber1024X448": {
		Algorithm:              "SphincsPlusShake",
		SphincsPlusParameterId: 1,
	},
	"SphincsPlusSHAKE_128f_Kyber1024X448": {
		Algorithm:              "SphincsPlusShake",
		SphincsPlusParameterId: 2,
	},
	"SphincsPlusSHAKE_192s_Kyber1024X448": {
		Algorithm:              "SphincsPlusShake",
		SphincsPlusParameterId: 3,
	},
	"SphincsPlusSHAKE_192f_Kyber1024X448": {
		Algorithm:              "SphincsPlusShake",
		SphincsPlusParameterId: 4,
	},
	"SphincsPlusSHAKE_256s_Kyber1024X448": {
		Algorithm:              "SphincsPlusShake",
		SphincsPlusParameterId: 5,
	},
	"SphincsPlusSHAKE_256f_Kyber1024X448": {
		Algorithm:              "SphincsPlusShake",
		SphincsPlusParameterId: 6,
	},
}

func benchmarkGenerateKey(b *testing.B, testData keyGenerateData) [][]byte {
	var serializedEntities [][]byte

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		key, err := GenerateKey(
			"Golang Gopher",
			"no-reply@golang.com",
			testData.Algorithm,
			testData.RSABits,
			testData.SphincsPlusParameterId,
		)

		serialized, err := key.Serialize()
		if err != nil {
			b.Fatal(err)
		}

		serializedEntities = append(serializedEntities, serialized)
	}

	return serializedEntities
}

func benchmarkParse(b *testing.B, keys [][]byte) []*KeyRing {
	var parsedKeys []*KeyRing

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		key, err := NewKeyFromReader(bytes.NewReader(keys[n]))
		if err != nil {
			b.Errorf("Failed to parse: %s", err)
			continue
		}

		keyring, err := NewKeyRing(key)
		if err != nil {
			b.Errorf("Failed to add to keyring: %s", err)
			continue
		}

		parsedKeys = append(parsedKeys, keyring)
	}

	return parsedKeys
}

func benchmarkEncrypt(b *testing.B, keys []*KeyRing, plaintext []byte, sign bool) [][]byte {
	var encryptedMessages [][]byte

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		plainMessage := NewPlainMessage(plaintext)
		keyring := keys[n%len(keys)]

		var signed *KeyRing
		if sign {
			signed = keyring
		}

		encrypted, err := keyring.Encrypt(plainMessage, signed)
		if err != nil {
			b.Errorf("Failed to encrypt: %s", err)
			continue
		}

		encryptedMessages = append(encryptedMessages, encrypted.GetBinary())
	}

	return encryptedMessages
}

func benchmarkDecrypt(b *testing.B, keys []*KeyRing, plaintext []byte, encryptedMessages [][]byte, verify bool) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pgpMessage := NewPGPMessage(encryptedMessages[n%len(encryptedMessages)])
		keyring := keys[n%len(keys)]

		var signed *KeyRing
		if verify {
			signed = keyring
		}

		decrypted, err := keyring.Decrypt(pgpMessage, signed, 0)
		if err != nil {
			b.Errorf("Failed to decrypt: %s", err)
			continue
		}

		if !bytes.Equal(decrypted.GetBinary(), plaintext) {
			b.Error("Decrypted wrong plaintext")
		}
	}
}

func benchmarkSign(b *testing.B, keys []*KeyRing, plaintext []byte) [][]byte {
	var signatures [][]byte

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		keyring := keys[n%len(keys)]
		plainMessage := NewPlainMessage(plaintext)

		sig, err := keyring.SignDetached(plainMessage)
		if err != nil {
			b.Errorf("Failed to sign: %s", err)
			continue
		}

		signatures = append(signatures, sig.GetBinary())
	}

	return signatures
}

func benchmarkVerify(b *testing.B, keys []*KeyRing, plaintext []byte, signatures [][]byte) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		keyring := keys[n%len(keys)]
		plainMessage := NewPlainMessage(plaintext)
		signature := NewPGPSignature(signatures[n%len(signatures)])

		err := keyring.VerifyDetached(plainMessage, signature, 0)

		if err != nil {
			b.Errorf("Signature error: %s", err)
		}
	}
}

func BenchmarkV6Keys(b *testing.B) {
	serializedKeys := make(map[string][][]byte)
	parsedKeys := make(map[string][]*KeyRing)
	encryptedMessages := make(map[string][][]byte)
	encryptedSignedMessages := make(map[string][][]byte)
	signatures := make(map[string][][]byte)

	var plaintext [benchmarkMessageSize]byte
	_, _ = rand.Read(plaintext[:])

	for name, config := range benchmarkTestSet {
		b.Run("Generate "+name, func(b *testing.B) {
			serializedKeys[name] = benchmarkGenerateKey(b, config)
			b.Logf("Generate %s: %d bytes", name, len(serializedKeys[name][0]))
		})
	}

	for name, keys := range serializedKeys {
		b.Run("Parse_"+name, func(b *testing.B) {
			parsedKeys[name] = benchmarkParse(b, keys)
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Encrypt_"+name, func(b *testing.B) {
			encryptedMessages[name] = benchmarkEncrypt(b, keys, plaintext[:], false)
			b.Logf("Encrypt %s: %d bytes", name, len(encryptedMessages[name][0]))
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Decrypt_"+name, func(b *testing.B) {
			benchmarkDecrypt(b, keys, plaintext[:], encryptedMessages[name], false)
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Encrypt_Sign_"+name, func(b *testing.B) {
			encryptedSignedMessages[name] = benchmarkEncrypt(b, keys, plaintext[:], true)
			b.Logf("Encrypt_Sign %s: %d bytes", name, len(encryptedSignedMessages[name][0]))
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Decrypt_Verify_"+name, func(b *testing.B) {
			benchmarkDecrypt(b, keys, plaintext[:], encryptedSignedMessages[name], true)
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Sign_"+name, func(b *testing.B) {
			signatures[name] = benchmarkSign(b, keys, plaintext[:])
			b.Logf("Sign %s: %d bytes", name, len(signatures[name][0]))
		})
	}

	for name, keys := range parsedKeys {
		b.Run("Verify_"+name, func(b *testing.B) {
			benchmarkVerify(b, keys, plaintext[:], signatures[name])
		})
	}
}
