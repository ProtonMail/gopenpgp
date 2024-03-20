package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

const messageToSign = "Hello World!"
const messageCleartext = "  Signed message\n  \n  "
const expectedMessageCleartext = "  Signed message\n\n"

func TestSignVerifyStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerifyStream(t, signer, verifier, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyStreamContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				SigningContext(NewSigningContext(testContext, true)).
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testSignVerifyStream(t, signer, verifier, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyStreamArmor(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerifyStream(t, signer, verifier, Armor, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerify(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerify(t, signer, verifier, false, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyUtf8(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Utf8().
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				Utf8().
				New()
			testSignVerify(t, signer, verifier, false, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Detached().
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerify(t, signer, verifier, true, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyDetachedUtf8(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Detached().
				Utf8().
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				Utf8().
				New()
			testSignVerify(t, signer, verifier, true, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyStreamDetached(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Detached().
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerifyDetachedStream(t, signer, verifier, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyStreamDetachedContext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Detached().
				SigningContext(NewSigningContext(testContext, true)).
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testSignVerifyDetachedStream(t, signer, verifier, Bytes, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyStreamDetachedArmor(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Detached().
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerifyDetachedStream(t, signer, verifier, Armor, len(material.keyRingTestPrivate.entities))
		})
	}
}

func TestSignVerifyCleartext(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				New()
			verifier, _ := material.pgp.Verify().
				VerificationKeys(material.keyRingTestPublic).
				New()
			testSignVerifyCleartext(t, signer, verifier)
		})
	}
}

func testSignVerify(
	t *testing.T,
	signer PGPSign,
	verifier PGPVerify,
	detached bool,
	encoding int8, //nolint:unparam
	numberOfSigsToVerify int,
) {
	messageBytes := []byte(messageToSign)
	signature, err := signer.Sign(messageBytes, encoding)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	var verifyResult *VerifyResult
	if detached {
		verifyResult, err = verifier.VerifyDetached(messageBytes, signature, encoding)
	} else {
		verifyDataResult, err := verifier.VerifyInline(signature, encoding)
		if err != nil {
			t.Fatal("Expected no error while verifying the message, got:", err)
		}
		if !bytes.Equal(messageBytes, verifyDataResult.Bytes()) {
			t.Fatal("Expected read message in verification to be equal to the input message")
		}
		verifyResult = &verifyDataResult.VerifyResult
	}
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if err = verifyResult.SignatureError(); err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
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

func testSignVerifyStream(
	t *testing.T,
	signer PGPSign,
	verifier PGPVerify,
	encoding int8,
	numberOfSigsToVerify int,
) {
	messageBytes := []byte(messageToSign)
	var messageBuffer bytes.Buffer
	signingWriter, err := signer.SigningWriter(&messageBuffer, encoding)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = signingWriter.Write(messageBytes)
	if err != nil {
		t.Fatal("Expected no error while writing message, got:", err)
	}
	err = signingWriter.Close()
	if err != nil {
		t.Fatal("Expected no error while sining message, got:", err)
	}

	verifyingReader, err := verifier.VerifyingReader(nil, &messageBuffer, encoding)
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	messageOut, err := verifyingReader.ReadAll()
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	verifyResult, err := verifyingReader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if err = verifyResult.SignatureError(); err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
	}
	if !bytes.Equal(messageOut, messageBytes) {
		t.Fatal("Expected read message in verification to be equal to the input message")
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

func testSignVerifyDetachedStream(
	t *testing.T,
	signer PGPSign,
	verifier PGPVerify,
	encoding int8,
	numberOfSigsToVerify int,
) {
	messageBytes := []byte(messageCleartext)
	var signatureBuffer bytes.Buffer
	signingWriter, err := signer.SigningWriter(&signatureBuffer, encoding)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	_, err = signingWriter.Write(messageBytes)
	if err != nil {
		t.Fatal("Expected no error while writing message, got:", err)
	}
	err = signingWriter.Close()
	if err != nil {
		t.Fatal("Expected no error while sining message, got:", err)
	}

	verifyingReader, _ := verifier.VerifyingReader(bytes.NewReader(messageBytes), &signatureBuffer, encoding)
	verifyResult, err := verifyingReader.DiscardAllAndVerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if err = verifyResult.SignatureError(); err != nil {
		t.Fatal("Expected no error while verifying the detached signature, got:", err)
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

func testSignVerifyCleartext(t *testing.T, signer PGPSign, verifier PGPVerify) {
	messageBytes := []byte(messageCleartext)
	cleartextMessage, err := signer.SignCleartext(messageBytes)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	result, err := verifier.VerifyCleartext(cleartextMessage)
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if err = result.SignatureError(); err != nil {
		t.Fatal("Expected no signature error while verifying the detached signature, got:", err)
	}
	assert.Exactly(t, expectedMessageCleartext, string(result.Cleartext()))
}
