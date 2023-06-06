package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"regexp"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/v2/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/ProtonMail/gopenpgp/v2/constants"
)

const signedPlainText = "Signed message\n"

var textSignature, binSignature []byte
var signatureTest = regexp.MustCompile("(?s)^-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")

func getSignatureType(sig []byte) (packet.SignatureType, error) {
	sigPacket, err := getSignaturePacket(sig)
	if err != nil {
		return 0, err
	}
	return sigPacket.SigType, nil
}

func testSignerText() PGPSign {
	signer, _ := testPGP.Sign().
		SigningKeys(keyRingTestPrivate).
		UTF8().
		Detached().
		New()
	return signer
}

func testSigner() PGPSign {
	signer, _ := testPGP.Sign().
		SigningKeys(keyRingTestPrivate).
		Detached().
		New()
	return signer
}

func testVerifier() PGPVerify {
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerifyTime(testTime).
		New()
	return verifier
}

func TestSignTextDetached(t *testing.T) {
	var err error

	textSignature, err = testSignerText().Sign([]byte(signedPlainText), nil)
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err := armor.ArmorPGPSignatureBinary(textSignature)
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	sigType, err := getSignatureType(textSignature)

	if err != nil {
		t.Fatal("Cannot get signature type:", err)
	}

	if sigType != packet.SigTypeText {
		t.Fatal("Signature type was not text")
	}

	assert.Regexp(t, signatureTest, string(armoredSignature))

	verificationError, _ := testVerifier().VerifyDetached([]byte(signedPlainText), textSignature)
	if verificationError.HasSignatureError() {
		t.Fatal("Cannot verify plaintext signature:", verificationError.SignatureError())
	}

	fakeMessage := []byte("wrong text")
	verificationError, _ = testVerifier().VerifyDetached(fakeMessage, textSignature)

	checkVerificationError(t, verificationError.SignatureError(), constants.SIGNATURE_FAILED)
}

func checkVerificationError(t *testing.T, err error, expectedStatus int) {
	if err == nil {
		t.Fatalf("Expected a verification error")
	}
	castedErr := &SignatureVerificationError{}
	isType := errors.As(err, castedErr)
	if !isType {
		t.Fatalf("Error was not a verification error: %v", err)
	}
	if castedErr.Status != expectedStatus {
		t.Fatalf("Expected status to be %d got %d", expectedStatus, castedErr.Status)
	}
}

func TestSignBinDetached(t *testing.T) {
	var err error

	binSignature, err = testSigner().Sign([]byte(signedPlainText), nil)
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err := armor.ArmorPGPSignatureBinary(binSignature)
	if err != nil {
		t.Fatal("Cannot armor signature:", err)
	}

	sigType, err := getSignatureType(binSignature)

	if err != nil {
		t.Fatal("Cannot get signature type:", err)
	}

	if sigType != packet.SigTypeBinary {
		t.Fatal("Signature type was not binary")
	}

	assert.Regexp(t, signatureTest, string(armoredSignature))

	verificationError, _ := testVerifier().VerifyDetached([]byte(signedPlainText), binSignature)
	if verificationError.HasSignatureError() {
		t.Fatal("Cannot verify binary signature:", verificationError.SignatureError())
	}
}

func Test_KeyRing_GetVerifiedSignatureTimestampSuccess(t *testing.T) {
	message := []byte(testMessage)
	var timeLocal int64 = 1600000000
	signer, _ := testPGP.Sign().
		SigningKeys(keyRingTestPrivate).
		SignTime(timeLocal).
		Detached().
		New()
	signature, err := signer.Sign(message, nil)
	if err != nil {
		t.Errorf("Got an error while generating the signature: %v", err)
	}
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerifyTime(timeLocal).
		New()
	verificationResult, _ := verifier.VerifyDetached(message, signature)
	actualTime := verificationResult.SignatureCreationTime()
	if err != nil {
		t.Errorf("Got an error while parsing the signature creation time: %v", err)
	}
	if timeLocal != actualTime {
		t.Errorf("Expected creation time to be %d, got %d", timeLocal, actualTime)
	}
}

func Test_KeyRing_GetVerifiedSignatureWithTwoKeysTimestampSuccess(t *testing.T) {
	publicKey1Armored, err := ioutil.ReadFile("testdata/signature/publicKey1")
	if err != nil {
		t.Errorf("Couldn't read the public key file: %v", err)
	}
	publicKey1 := parseKey(t, string(publicKey1Armored))
	publicKey2Armored, err := ioutil.ReadFile("testdata/signature/publicKey2")
	if err != nil {
		t.Errorf("Couldn't read the public key file: %v", err)
	}
	publicKey2 := parseKey(t, string(publicKey2Armored))
	message := []byte("hello world")
	signatureArmored, err := ioutil.ReadFile("testdata/signature/detachedSigSignedTwice")
	if err != nil {
		t.Errorf("Couldn't read the signature file: %v", err)
	}
	signature, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Errorf("Got an error while parsing the signature: %v", err)
	}
	time1 := getTimestampOfIssuer(signature, publicKey1.GetKeyID())
	time2 := getTimestampOfIssuer(signature, publicKey2.GetKeyID())
	keyRing, err := NewKeyRing(publicKey1)
	if err != nil {
		t.Errorf("Got an error while building the key ring: %v", err)
	}
	err = keyRing.AddKey(publicKey2)
	if err != nil {
		t.Errorf("Got an error while adding key 2 to the key ring: %v", err)
	}

	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRing).
		DisableVerifyTimeCheck().
		New()

	verificationResult, _ := verifier.VerifyDetached(message, signature)
	actualTime := verificationResult.SignatureCreationTime()
	if err != nil {
		t.Errorf("Got an error while parsing the signature creation time: %v", err)
	}
	if time2 != actualTime {
		t.Errorf("Expected creation time to be %d, got %d", time1, actualTime)
	}
	if time1 == actualTime {
		t.Errorf("Expected creation time to be different from %d", time1)
	}
}

func parseKey(t *testing.T, keyArmored string) *Key {
	key, err := NewKeyFromArmored(keyArmored)
	if err != nil {
		t.Errorf("Couldn't parse key: %v", err)
		return nil
	}
	return key
}

func getTimestampOfIssuer(signature []byte, keyID uint64) int64 {
	packets := packet.NewReader(bytes.NewReader(signature))
	var err error
	var p packet.Packet
	for {
		p, err = packets.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			continue
		}
		sigPacket, ok := p.(*packet.Signature)
		if !ok {
			continue
		}
		var outBuf bytes.Buffer
		err = sigPacket.Serialize(&outBuf)
		if err != nil {
			continue
		}
		if *sigPacket.IssuerKeyId == keyID {
			return sigPacket.CreationTime.Unix()
		}
	}
	return -1
}

func Test_KeyRing_GetVerifiedSignatureTimestampError(t *testing.T) {
	message := []byte(testMessage)
	var timeLocal int64 = 1600000000
	signer, _ := testPGP.Sign().
		SignTime(timeLocal).
		SigningKeys(keyRingTestPrivate).
		Detached().
		New()
	signature, err := signer.Sign(message, nil)
	if err != nil {
		t.Errorf("Got an error while generating the signature: %v", err)
	}
	messageCorrupted := []byte("Ciao world!")
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerifyTime(timeLocal).
		New()
	verificationResult, _ := verifier.VerifyDetached(messageCorrupted, signature)
	if !verificationResult.HasSignatureError() {
		t.Errorf("Expected an error while parsing the creation time of a wrong signature, got nil")
	}
}

func Test_SignDetachedWithNonCriticalContext(t *testing.T) {
	// given

	context := NewSigningContext(
		"test-context",
		false,
	)
	signer, _ := testPGP.Sign().
		SigningKeys(keyRingTestPrivate).
		SigningContext(context).
		Detached().
		New()
	// when
	signature, err := signer.Sign([]byte(testMessage), nil)
	// then
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(signature))
	if err != nil {
		t.Fatal(err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		t.Fatal("Packet was not a signature")
	}
	notations := sig.Notations
	if len(notations) != 1 {
		t.Fatal("Wrong number of notations")
	}
	notation := notations[0]
	if notation.Name != constants.SignatureContextName {
		t.Fatalf("Expected notation name to be %s, got %s", constants.SignatureContextName, notation.Name)
	}
	if string(notation.Value) != context.Value {
		t.Fatalf("Expected notation value to be %s, got %s", context.Value, notation.Value)
	}
	if notation.IsCritical {
		t.Fatal("Expected notation to be non critical")
	}
	if !notation.IsHumanReadable {
		t.Fatal("Expected notation to be human readable")
	}
}

func Test_SignDetachedWithCriticalContext(t *testing.T) {
	// given

	context := NewSigningContext(
		"test-context",
		true,
	)
	signer, _ := testPGP.Sign().
		SigningKeys(keyRingTestPrivate).
		SigningContext(context).
		Detached().
		New()
	// when
	signature, err := signer.Sign([]byte(testMessage), nil)
	// then
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(signature))
	if err != nil {
		t.Fatal(err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		t.Fatal("Packet was not a signature")
	}
	notations := sig.Notations
	if len(notations) != 1 {
		t.Fatal("Wrong number of notations")
	}
	notation := notations[0]
	if notation.Name != constants.SignatureContextName {
		t.Fatalf("Expected notation name to be %s, got %s", constants.SignatureContextName, notation.Name)
	}
	if string(notation.Value) != context.Value {
		t.Fatalf("Expected notation value to be %s, got %s", context.Value, notation.Value)
	}
	if !notation.IsCritical {
		t.Fatal("Expected notation to be critical")
	}
	if !notation.IsHumanReadable {
		t.Fatal("Expected notation to be human readable")
	}
}

func Test_VerifyWithUnknownCriticalContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}

	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	checkVerificationError(t, result.SignatureError(), constants.SIGNATURE_FAILED)
}

func Test_VerifyWithUnKnownNonCriticalContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/non_critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	if result.HasSignatureError() {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyWithKnownCriticalContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		false,
		0,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	if result.HasSignatureError() {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyWithWrongContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"another-test-context",
		false,
		0,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	checkVerificationError(t, result.SignatureError(), constants.SIGNATURE_BAD_CONTEXT)
}

func Test_VerifyWithMissingNonRequiredContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		false,
		0,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	if result.HasSignatureError() {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyWithMissingRequiredContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		true,
		0,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	checkVerificationError(t, result.SignatureError(), constants.SIGNATURE_BAD_CONTEXT)
}

func Test_VerifyWithMissingRequiredContextBeforeCutoff(t *testing.T) {
	// given
	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		t.Fatal(err)
	}
	sigPacket, ok := p.(*packet.Signature)
	if !ok {
		t.Fatal("Packet was not a signature")
	}
	verificationContext := NewVerificationContext(
		"test-context",
		true,
		sigPacket.CreationTime.Unix()+10000,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	if result.HasSignatureError() {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyWithMissingRequiredContextAfterCutoff(t *testing.T) {
	// given
	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		t.Fatal(err)
	}
	sigPacket, ok := p.(*packet.Signature)
	if !ok {
		t.Fatal("Packet was not a signature")
	}
	verificationContext := NewVerificationContext(
		"test-context",
		true,
		sigPacket.CreationTime.Unix()-10000,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	checkVerificationError(t, result.SignatureError(), constants.SIGNATURE_BAD_CONTEXT)
}

func Test_VerifyWithDoubleContext(t *testing.T) {
	// given
	signatureArmored, err := ioutil.ReadFile("testdata/signature/double_critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := armor.UnarmorBytes(signatureArmored)
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		true,
		0,
	)
	// when
	verifier, _ := testPGP.Verify().
		VerifyKeys(keyRingTestPublic).
		VerificationContext(verificationContext).
		DisableVerifyTimeCheck().
		New()
	result, _ := verifier.VerifyDetached([]byte(testMessage), sig)
	// then
	checkVerificationError(t, result.SignatureError(), constants.SIGNATURE_BAD_CONTEXT)
}

func Test_verifySignaturExpire(t *testing.T) {
	defer func(t int64) { pgp.latestServerTime = t }(pgp.latestServerTime)
	pgp.latestServerTime = 0

	const lifetime = uint32(time.Hour / time.Second)

	cfg := &packet.Config{
		Algorithm:              packet.PubKeyAlgoEdDSA,
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        lifetime,
		SigLifetimeSecs:        lifetime,
	}

	entity, err := openpgp.NewEntity("John Smith", "Linux", "john.smith@example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}

	key, err := NewKeyFromEntity(entity)
	if err != nil {
		t.Fatal(err)
	}

	keyRing, err := NewKeyRing(key)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("Hello, World!")
	message := NewPlainMessage(data)

	signature, err := keyRing.SignDetached(message)
	if err != nil {
		t.Fatalf("%#+v", err)
	}

	sig := NewPGPSignature(signature.GetBinary())

	// packet.PublicKey.KeyExpired will return false here because PublicKey CreationTime has
	// nanosecond precision, while pgpcrypto.GetUnixTime() has only second precision.
	// Adjust the check time to be in the future to ensure that the key is not expired.
	err = keyRing.VerifyDetached(message, sig, GetUnixTime()+1)
	if err != nil {
		t.Fatal(err)
	}
}
