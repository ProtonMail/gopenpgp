package crypto

import (
	"testing"
)

const wrongTestContext = "wrong-context"

var wrongPassword = []byte("wrong-password")

func TestDecryptWrongKey(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKey(material.keyWrong).
				New()

			pgpMessage, err := encHandle.Encrypt([]byte(testMessage))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decHandle.Decrypt(pgpMessage.Bytes(), Bytes); err == nil {
				t.Fatal("should not decrypt with wrong key")
			}
		})
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Password(password).
				New()
			decHandle, _ := material.pgp.Decryption().
				Password(wrongPassword).
				New()

			pgpMessage, err := encHandle.Encrypt([]byte(testMessage))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decHandle.Decrypt(pgpMessage.Bytes(), Bytes); err == nil {
				t.Fatal("should not decrypt with wrong password")
			}
		})
	}
}

func TestDecryptWrongSessionKey(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			wrongSessionKeyBytes := make([]byte, len(material.testSessionKey.Key))
			copy(wrongSessionKeyBytes, material.testSessionKey.Key)
			wrongSessionKeyBytes[0] += 1
			wrongSessionKey := NewSessionKeyFromToken(wrongSessionKeyBytes, material.testSessionKey.Algo)

			encHandle, _ := material.pgp.Encryption().
				SessionKey(material.testSessionKey).
				New()
			decHandle, _ := material.pgp.Decryption().
				SessionKey(wrongSessionKey).
				New()

			pgpMessage, err := encHandle.Encrypt([]byte(testMessage))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decHandle.Decrypt(pgpMessage.Bytes(), Bytes); err == nil {
				t.Fatal("Should not decrypt with wrong session key")
			}
		})
	}
}

func TestDecryptVerifyWrongKey(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKey(material.keyWrong).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testVerificationFails(
				t,
				encHandle,
				decHandle,
				"Signature verification must fail with wrong key",
			)
		})
	}
}

func TestDecryptVerifyWrongContext(t *testing.T) {
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
				VerificationContext(NewVerificationContext(wrongTestContext, true, 0)).
				New()
			testVerificationFails(
				t,
				encHandle,
				decHandle,
				"Signature verification must fail with wrong context",
			)
		})
	}
}

func TestDecryptVerifyWrongContextMissing(t *testing.T) {
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
				New()
			testVerificationFails(
				t,
				encHandle,
				decHandle,
				"Signature verification must fail with no context",
			)
		})
	}
}

func TestDecryptVerifyNoContextButRequired(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(wrongTestContext, true, 0)).
				New()
			testVerificationFails(
				t,
				encHandle,
				decHandle,
				"Signature verification must fail with no context",
			)
		})
	}
}

func TestDecryptVerifyNoCriticalContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, false)).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				New()
			testVerificationSuccess(t, encHandle, decHandle)
		})
	}
}

func TestDecryptVerifyNoCriticalContextVerify(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			encHandle, _ := material.pgp.Encryption().
				Recipients(material.keyRingTestPublic).
				SigningKeys(material.keyRingTestPrivate).
				New()
			decHandle, _ := material.pgp.Decryption().
				DecryptionKeys(material.keyRingTestPrivate).
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, false, 0)).
				New()
			testVerificationSuccess(t, encHandle, decHandle)
		})
	}
}

func testVerificationFails(
	t *testing.T,
	encHandle PGPEncryption,
	decHandle PGPDecryption,
	failure string,
) {
	pgpMessage, err := encHandle.Encrypt([]byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	verifyResult, err := decHandle.Decrypt(pgpMessage.Bytes(), Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if verifyResult.SignatureError() == nil {
		t.Fatal(failure)
	}
}

func testVerificationSuccess(
	t *testing.T,
	encHandle PGPEncryption,
	decHandle PGPDecryption,
) {
	pgpMessage, err := encHandle.Encrypt([]byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	verifyResult, err := decHandle.Decrypt(pgpMessage.Bytes(), Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if verifyResult.SignatureError() != nil {
		t.Fatal("Expected no signature failure")
	}
}
