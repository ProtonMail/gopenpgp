package crypto

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"io/ioutil"
	"regexp"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"

	"github.com/ProtonMail/gopenpgp/v2/constants"
)

const testMessage = "Hello world!"

const signedPlainText = "Signed message\n"

var textSignature, binSignature *PGPSignature
var message *PlainMessage
var signatureTest = regexp.MustCompile("(?s)^-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")

func getSignatureType(sig *PGPSignature) (packet.SignatureType, error) {
	sigPacket, err := getSignaturePacket(sig)
	if err != nil {
		return 0, err
	}
	return sigPacket.SigType, nil
}

func getSignaturePacket(sig *PGPSignature) (*packet.Signature, error) {
	p, err := packet.Read(bytes.NewReader(sig.Data))
	if err != nil {
		return nil, err
	}
	sigPacket, ok := p.(*packet.Signature)
	if !ok {
		return nil, errors.New("")
	}
	return sigPacket, nil
}

func TestSignTextDetached(t *testing.T) {
	var err error

	message = NewPlainMessageFromString(signedPlainText)
	textSignature, err = keyRingTestPrivate.SignDetached(message)
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err := textSignature.GetArmored()
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

	assert.Regexp(t, signatureTest, armoredSignature)
}

func TestVerifyTextDetachedSig(t *testing.T) {
	verificationError := keyRingTestPublic.VerifyDetached(message, textSignature, testTime)
	if verificationError != nil {
		t.Fatal("Cannot verify plaintext signature:", verificationError)
	}
}

func checkVerificationError(t *testing.T, err error, expectedStatus int) {
	if err == nil {
		t.Fatalf("Expected a verification error")
	}
	castedErr := &SignatureVerificationError{}
	isType := errors.As(err, castedErr)
	if !isType {
		t.Fatalf("Error was not a verification errror: %v", err)
	}
	if castedErr.Status != expectedStatus {
		t.Fatalf("Expected status to be %d got %d", expectedStatus, castedErr.Status)
	}
}

func TestVerifyTextDetachedSigWrong(t *testing.T) {
	fakeMessage := NewPlainMessageFromString("wrong text")
	verificationError := keyRingTestPublic.VerifyDetached(fakeMessage, textSignature, testTime)

	checkVerificationError(t, verificationError, constants.SIGNATURE_FAILED)

	err := &SignatureVerificationError{}
	_ = errors.As(verificationError, err)
	assert.Exactly(t, constants.SIGNATURE_FAILED, err.Status)
}

func TestSignBinDetached(t *testing.T) {
	var err error

	message = NewPlainMessage([]byte(signedPlainText))
	binSignature, err = keyRingTestPrivate.SignDetached(message)
	if err != nil {
		t.Fatal("Cannot generate signature:", err)
	}

	armoredSignature, err := binSignature.GetArmored()
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

	assert.Regexp(t, signatureTest, armoredSignature)
}

func TestVerifyBinDetachedSig(t *testing.T) {
	verificationError := keyRingTestPublic.VerifyDetached(message, binSignature, testTime)
	if verificationError != nil {
		t.Fatal("Cannot verify binary signature:", verificationError)
	}
}

func Test_KeyRing_GetVerifiedSignatureTimestampSuccess(t *testing.T) {
	message := NewPlainMessageFromString(testMessage)
	var time int64 = 1600000000
	pgp.latestServerTime = time
	defer func() {
		pgp.latestServerTime = testTime
	}()
	signature, err := keyRingTestPrivate.SignDetached(message)
	if err != nil {
		t.Errorf("Got an error while generating the signature: %v", err)
	}
	actualTime, err := keyRingTestPublic.GetVerifiedSignatureTimestamp(message, signature, 0)
	if err != nil {
		t.Errorf("Got an error while parsing the signature creation time: %v", err)
	}
	if time != actualTime {
		t.Errorf("Expected creation time to be %d, got %d", time, actualTime)
	}
}

func Test_KeyRing_GetVerifiedSignatureTimestampWithContext(t *testing.T) {
	message := NewPlainMessageFromString(testMessage)
	var time int64 = 1600000000
	pgp.latestServerTime = time
	defer func() {
		pgp.latestServerTime = testTime
	}()
	var testContext = "test-context"
	signature, err := keyRingTestPrivate.SignDetachedWithContext(message, NewSigningContext(testContext, true))
	if err != nil {
		t.Errorf("Got an error while generating the signature: %v", err)
	}
	actualTime, err := keyRingTestPublic.GetVerifiedSignatureTimestampWithContext(message, signature, 0, NewVerificationContext(testContext, true, 0))
	if err != nil {
		t.Errorf("Got an error while parsing the signature creation time: %v", err)
	}
	if time != actualTime {
		t.Errorf("Expected creation time to be %d, got %d", time, actualTime)
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
	message := NewPlainMessageFromString("hello world")
	signatureArmored, err := ioutil.ReadFile("testdata/signature/detachedSigSignedTwice")
	if err != nil {
		t.Errorf("Couldn't read the signature file: %v", err)
	}
	signature, err := NewPGPSignatureFromArmored(string(signatureArmored))
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
	actualTime, err := keyRing.GetVerifiedSignatureTimestamp(message, signature, 0)
	if err != nil {
		t.Errorf("Got an error while parsing the signature creation time: %v", err)
	}
	if time1 != actualTime {
		t.Errorf("Expected creation time to be %d, got %d", time1, actualTime)
	}
	if time2 == actualTime {
		t.Errorf("Expected creation time to be different from %d", time2)
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

func getTimestampOfIssuer(signature *PGPSignature, keyID uint64) int64 {
	packets := packet.NewReader(bytes.NewReader(signature.Data))
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
	message := NewPlainMessageFromString(testMessage)
	var time int64 = 1600000000
	pgp.latestServerTime = time
	defer func() {
		pgp.latestServerTime = testTime
	}()
	signature, err := keyRingTestPrivate.SignDetached(message)
	if err != nil {
		t.Errorf("Got an error while generating the signature: %v", err)
	}
	messageCorrupted := NewPlainMessageFromString("Ciao world!")
	_, err = keyRingTestPublic.GetVerifiedSignatureTimestamp(messageCorrupted, signature, 0)
	if err == nil {
		t.Errorf("Expected an error while parsing the creation time of a wrong signature, got nil")
	}
}

func Test_SignDetachedWithNonCriticalContext(t *testing.T) {
	// given

	context := NewSigningContext(
		"test-context",
		false,
	)
	// when
	signature, err := keyRingTestPrivate.SignDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		context,
	)
	// then
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(signature.Data))
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
	// when
	signature, err := keyRingTestPrivate.SignDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		context,
	)
	// then
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(signature.Data))
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

func Test_VerifyDetachedWithUnknownCriticalContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}

	// when
	err = keyRingTestPublic.VerifyDetached(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
	)
	// then
	checkVerificationError(t, err, constants.SIGNATURE_FAILED)
}

func Test_VerifyDetachedWithUnKnownNonCriticalContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/non_critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	// when
	err = keyRingTestPublic.VerifyDetached(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
	)
	// then
	if err != nil {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyDetachedWithKnownCriticalContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		false,
		0,
	)
	// when
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	if err != nil {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyDetachedWithWrongContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"another-test-context",
		false,
		0,
	)
	// when
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	checkVerificationError(t, err, constants.SIGNATURE_BAD_CONTEXT)
}

func Test_VerifyDetachedWithMissingNonRequiredContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		false,
		0,
	)
	// when
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	if err != nil {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyDetachedWithMissingRequiredContext(t *testing.T) {
	// given

	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		true,
		0,
	)
	// when
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	checkVerificationError(t, err, constants.SIGNATURE_BAD_CONTEXT)
}

func Test_VerifyDetachedWithMissingRequiredContextBeforeCutoff(t *testing.T) {
	// given
	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(sig.Data))
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
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	if err != nil {
		t.Fatalf("Expected no verification error, got %v", err)
	}
}

func Test_VerifyDetachedWithMissingRequiredContextAfterCutoff(t *testing.T) {
	// given
	signatureArmored, err := ioutil.ReadFile("testdata/signature/no_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	p, err := packet.Read(bytes.NewReader(sig.Data))
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
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	checkVerificationError(t, err, constants.SIGNATURE_BAD_CONTEXT)
}

func Test_VerifyDetachedWithDoubleContext(t *testing.T) {
	// given
	signatureArmored, err := ioutil.ReadFile("testdata/signature/double_critical_context_detached_sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewPGPSignatureFromArmored(string(signatureArmored))
	if err != nil {
		t.Fatal(err)
	}
	verificationContext := NewVerificationContext(
		"test-context",
		true,
		0,
	)
	// when
	err = keyRingTestPublic.VerifyDetachedWithContext(
		NewPlainMessage([]byte(testMessage)),
		sig,
		0,
		verificationContext,
	)
	// then
	checkVerificationError(t, err, constants.SIGNATURE_BAD_CONTEXT)
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
