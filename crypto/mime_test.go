package crypto

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Corresponding key in testdata/mime_privateKey.
var MIMEKeyPassword = []byte("test")

type Callbacks struct {
	Testing *testing.T
}

func (t *Callbacks) OnBody(body string, mimetype string) {
	assert.Exactly(t.Testing, readTestFile("mime_decryptedBody", false), body)
}

func (t Callbacks) OnAttachment(headers string, data []byte) {
	assert.Exactly(t.Testing, 1, data)
}

func (t Callbacks) OnEncryptedHeaders(headers string) {
	assert.Exactly(t.Testing, "", headers)
}

func (t Callbacks) OnVerified(verified int) {
}

func (t Callbacks) OnError(err error) {
	t.Testing.Fatal("Error in decrypting MIME message: ", err)
}

func TestDecrypt(t *testing.T) {
	callbacks := Callbacks{
		Testing: t,
	}

	privateKey, err := NewKeyFromArmored(readTestFile("mime_privateKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor private key:", err)
	}

	privateKey, err = privateKey.Unlock(MIMEKeyPassword)
	if err != nil {
		t.Fatal("Cannot unlock private key:", err)
	}

	privateKeyRing, err := NewKeyRing(privateKey)
	if err != nil {
		t.Fatal("Cannot create private keyring:", err)
	}

	message, err := NewPGPMessageFromArmored(readTestFile("mime_pgpMessage", false))
	if err != nil {
		t.Fatal("Cannot decode armored message:", err)
	}

	privateKeyRing.DecryptMIMEMessage(
		message,
		nil,
		&callbacks,
		GetUnixTime())
}

func TestParse(t *testing.T) {
	body, atts, attHeaders, err := parseMIME(readTestFile("mime_testMessage", false), nil)

	if err != nil {
		t.Fatal("Expected no error while parsing message, got:", err)
	}

	_ = atts
	_ = attHeaders

	bodyData, _ := body.GetBody()
	assert.Exactly(t, readTestFile("mime_decodedBody", true), bodyData)
	assert.Exactly(t, readTestFile("mime_decodedBodyHeaders", false), body.GetHeaders())
	assert.Exactly(t, 2, len(atts))
}

type testMIMECallbacks struct {
	onBody       []struct{ body, mimetype string }
	onAttachment []struct {
		headers string
		data    []byte
	}
	onEncryptedHeaders []string
	onVerified         []int
	onError            []error
}

func (tc *testMIMECallbacks) OnBody(body string, mimetype string) {
	tc.onBody = append(tc.onBody, struct {
		body     string
		mimetype string
	}{body, mimetype})
}

func (tc *testMIMECallbacks) OnAttachment(headers string, data []byte) {
	tc.onAttachment = append(tc.onAttachment, struct {
		headers string
		data    []byte
	}{headers, data})
}

func (tc *testMIMECallbacks) OnEncryptedHeaders(headers string) {
	tc.onEncryptedHeaders = append(tc.onEncryptedHeaders, headers)
}

func (tc *testMIMECallbacks) OnVerified(status int) {
	tc.onVerified = append(tc.onVerified, status)
}

func (tc *testMIMECallbacks) OnError(err error) {
	tc.onError = append(tc.onError, err)
}

func loadPrivateKeyRing(file string, passphrase string) (*KeyRing, error) {
	armored, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	key, err := NewKeyFromArmored(string(armored))
	if err != nil {
		return nil, err
	}
	unlockedKey, err := key.Unlock([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	keyRing, err := NewKeyRing(unlockedKey)
	if err != nil {
		return nil, err
	}
	return keyRing, nil
}

func loadPublicKeyRing(file string) (*KeyRing, error) {
	armored, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	key, err := NewKeyFromArmored(string(armored))
	if err != nil {
		return nil, err
	}
	if key.IsPrivate() {
		publicKey, err := key.GetPublicKey()
		if err != nil {
			return nil, err
		}
		key, err = NewKey(publicKey)
		if err != nil {
			return nil, err
		}
	}
	keyRing, err := NewKeyRing(key)
	if err != nil {
		return nil, err
	}
	return keyRing, nil
}

func loadMessage(file string) (*PGPMessage, error) {
	armored, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	message, err := NewPGPMessageFromArmored(string(armored))
	if err != nil {
		return nil, err
	}
	return message, nil
}

func runScenario(t *testing.T, messageFile string) *testMIMECallbacks {
	decryptionKeyRing, err := loadPrivateKeyRing("testdata/mime/decryption-key.asc", "test_passphrase")
	if err != nil {
		t.Errorf("Failed to load decryption key %v", err)
	}
	verificationKeyRing, err := loadPublicKeyRing("testdata/mime/verification-key.asc")
	if err != nil {
		t.Errorf("Failed to load verification key %v", err)
	}
	message, err := loadMessage(messageFile)
	if err != nil {
		t.Errorf("Failed to load message %v", err)
	}
	callbacks := &testMIMECallbacks{}
	decryptionKeyRing.DecryptMIMEMessage(message, verificationKeyRing, callbacks, 0)
	return callbacks
}

func compareStatus(expected []int, actual []int, t *testing.T) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %v, got %v", expected, actual)
	} else {
		for i, actualStatus := range actual {
			if actualStatus != expected[i] {
				t.Errorf("Expected status %v, got %v", expected[i], actualStatus)
			}
		}
	}
}

func TestMessageVerificationOkOk(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_00.asc")
	if len(callbackResults.onError) != 0 {
		for _, err := range callbackResults.onError {
			t.Errorf("Expected no errors got %v", err)
		}
	}
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationOkNotSigned(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_01.asc")
	if len(callbackResults.onError) != 0 {
		for _, err := range callbackResults.onError {
			t.Errorf("Expected no errors got %v", err)
		}
	}
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationOkNoVerifier(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_02.asc")
	if len(callbackResults.onError) != 0 {
		for _, err := range callbackResults.onError {
			t.Errorf("Expected no errors got %v", err)
		}
	}
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationOkFailed(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_03.asc")
	if len(callbackResults.onError) != 0 {
		for _, err := range callbackResults.onError {
			t.Errorf("Expected no errors got %v", err)
		}
	}
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNotSignedOk(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_10.asc")
	if len(callbackResults.onError) != 0 {
		for _, err := range callbackResults.onError {
			t.Errorf("Expected no errors got %v", err)
		}
	}
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func checkIsSigErr(t *testing.T, err error) int {
	sigErr := &SignatureVerificationError{}
	if errors.As(err, &sigErr) {
		return sigErr.Status
	}
	t.Errorf("Expected a signature verification error, got %v", err)
	return -1
}

func compareErrors(expected []SignatureVerificationError, actual []error, t *testing.T) {
	if len(actual) != len(expected) {
		t.Errorf("Expected %v, got %v", expected, actual)
	} else {
		for i, err := range actual {
			actualStatus := checkIsSigErr(t, err)
			if actualStatus != expected[i].Status {
				t.Errorf("Expected sig error with status %v, got %v", expected[i].Status, actualStatus)
			}
		}
	}
}

func TestMessageVerificationNotSignedNotSigned(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_11.asc")
	var expectedErrors = []SignatureVerificationError{newSignatureNotSigned(), newSignatureNotSigned()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{1}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNotSignedNoVerifier(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_12.asc")
	var expectedErrors = []SignatureVerificationError{newSignatureNotSigned(), newSignatureNoVerifier()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{2}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNotSignedFailed(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_13.asc")
	var expectedErrors = []SignatureVerificationError{newSignatureNotSigned(), newSignatureFailed(nil)}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{3}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierOk(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_20.asc")
	var expectedErrors = []SignatureVerificationError{}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierNotSigned(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_21.asc")
	var expectedErrors = []SignatureVerificationError{newSignatureNoVerifier(), newSignatureNotSigned()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{2}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierNoVerifier(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_22.asc")
	var expectedErrors = []SignatureVerificationError{newSignatureNoVerifier(), newSignatureNoVerifier()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{2}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierFailed(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_23.asc")
	var expectedErrors = []SignatureVerificationError{newSignatureNoVerifier(), newSignatureFailed(nil)}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{3}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}
