package crypto

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/internal"
	"github.com/stretchr/testify/assert"
)

const messageToSign = "Hello World!"
const messageCleartext = "  Signed message\n  \n  "

func TestSignVerifyStream(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				New()
			verifier, _ := material.pgp.Verify().
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerifyStream(t, signer, verifier)
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
				VerifyKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testSignVerifyStream(t, signer, verifier)
		})
	}
}

func TestSignVerifyStreamArmor(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Armor().
				New()
			verifier, _ := material.pgp.Verify().
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerifyStream(t, signer, verifier)
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
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerify(t, signer, verifier, false)
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
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerify(t, signer, verifier, true)
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
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerifyDetachedStream(t, signer, verifier)
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
				VerifyKeys(material.keyRingTestPublic).
				VerificationContext(NewVerificationContext(testContext, true, 0)).
				New()
			testSignVerifyDetachedStream(t, signer, verifier)
		})
	}
}

func TestSignVerifyStreamDetachedArmor(t *testing.T) {
	for _, material := range testMaterialForProfiles {
		t.Run(material.profileName, func(t *testing.T) {
			signer, _ := material.pgp.Sign().
				SigningKeys(material.keyRingTestPrivate).
				Detached().
				Armor().
				New()
			verifier, _ := material.pgp.Verify().
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerifyDetachedStream(t, signer, verifier)
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
				VerifyKeys(material.keyRingTestPublic).
				New()
			testSignVerifyCleartext(t, signer, verifier)
		})
	}
}

func testSignVerify(t *testing.T, signer PGPSign, verifier PGPVerify, detached bool) {
	messageBytes := []byte(messageToSign)
	signature, err := signer.Sign(messageBytes)
	if err != nil {
		t.Fatal("Expected no error while signing the message, got:", err)
	}
	var verifyResult *VerifyResult
	if detached {
		verifyResult, err = verifier.VerifyDetached(messageBytes, signature)
	} else {
		verifyDataResult, err := verifier.VerifyInline(signature)
		if err != nil {
			t.Fatal("Expected no error while verifying the message, got:", err)
		}
		if !bytes.Equal(messageBytes, verifyDataResult.Result()) {
			t.Fatal("Expected read message in verification to be equal to the input message")
		}
		verifyResult = &verifyDataResult.VerifyResult
	}
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if verifyResult.HasSignatureError() {
		t.Fatal("Expected no error while verifying the detached signature, got:", verifyResult.SignatureError())
	}

}

func testSignVerifyStream(t *testing.T, signer PGPSign, verifier PGPVerify) {
	messageBytes := []byte(messageToSign)
	var messageBuffer bytes.Buffer
	signingWriter, err := signer.SigningWriter(&messageBuffer)
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

	verifyingReader, err := verifier.VerifyingReader(nil, &messageBuffer)
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	messageOut, err := verifyingReader.ReadAll()
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	result, err := verifyingReader.VerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if result.HasSignatureError() {
		t.Fatal("Expected no error while verifying the detached signature, got:", result.SignatureError())
	}
	if !bytes.Equal(messageOut, messageBytes) {
		t.Fatal("Expected read message in verification to be equal to the input message")
	}
}

func testSignVerifyDetachedStream(t *testing.T, signer PGPSign, verifier PGPVerify) {
	messageBytes := []byte(messageToSign)
	var signatureBuffer bytes.Buffer
	signingWriter, err := signer.SigningWriter(&signatureBuffer)
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

	verifyingReader, _ := verifier.VerifyingReader(bytes.NewReader(messageBytes), &signatureBuffer)
	result, err := verifyingReader.DiscardAllAndVerifySignature()
	if err != nil {
		t.Fatal("Expected no error while verifying the message, got:", err)
	}
	if result.HasSignatureError() {
		t.Fatal("Expected no error while verifying the detached signature, got:", result.SignatureError())
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
	if result.HasSignatureError() {
		t.Fatal("Expected no signature error while verifying the detached signature, got:", result.SignatureError())
	}
	assert.Exactly(t, internal.Canonicalize(internal.TrimEachLine(messageCleartext)), string(result.Cleartext()))
}
