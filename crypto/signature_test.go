package crypto

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/stretchr/testify/assert"
)

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

func TestVerifyTextDetachedSigWrong(t *testing.T) {
	fakeMessage := NewPlainMessageFromString("wrong text")
	verificationError := keyRingTestPublic.VerifyDetached(fakeMessage, textSignature, testTime)

	assert.EqualError(t, verificationError, "Signature Verification Error: Invalid signature")

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
	message := NewPlainMessageFromString("Hello world!")
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
	message := NewPlainMessageFromString("Hello world!")
	var time int64 = 1600000000
	pgp.latestServerTime = time
	defer func() {
		pgp.latestServerTime = testTime
	}()
	signature, err := keyRingTestPrivate.SignDetached(message)
	if err != nil {
		t.Errorf("Got an error while generating the signature: %v", err)
	}
	message_corrupted := NewPlainMessageFromString("Ciao world!")
	_, err = keyRingTestPublic.GetVerifiedSignatureTimestamp(message_corrupted, signature, 0)
	if err == nil {
		t.Errorf("Expected an error while parsing the creation time of a wrong signature, got nil")
	}
}
