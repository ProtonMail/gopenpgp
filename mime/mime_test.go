package mime

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
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

	privateKey, err := crypto.NewKeyFromArmored(readTestFile("mime_privateKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor private key:", err)
	}

	privateKey, err = privateKey.Unlock(MIMEKeyPassword)
	if err != nil {
		t.Fatal("Cannot unlock private key:", err)
	}

	privateKeyRing, err := crypto.NewKeyRing(privateKey)
	if err != nil {
		t.Fatal("Cannot create private keyring:", err)
	}

	message := readTestFileBytes("mime_pgpMessage")
	pgp := crypto.PGP()
	decHandle, _ := pgp.Decryption().DecryptionKeys(privateKeyRing).New()
	Decrypt(message, crypto.Armor, decHandle, nil, &callbacks)
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

func loadPrivateKeyRing(file string, passphrase string) (*crypto.KeyRing, error) {
	armored, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	unlockedKey, err := crypto.NewPrivateKeyFromArmored(string(armored), []byte(passphrase))
	if err != nil {
		return nil, err
	}
	keyRing, err := crypto.NewKeyRing(unlockedKey)
	if err != nil {
		return nil, err
	}
	return keyRing, nil
}

func loadPublicKeyRing(file string) (*crypto.KeyRing, error) {
	armored, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	key, err := crypto.NewKeyFromArmored(string(armored))
	if err != nil {
		return nil, err
	}
	if key.IsPrivate() {
		publicKey, err := key.GetPublicKey()
		if err != nil {
			return nil, err
		}
		key, err = crypto.NewKey(publicKey)
		if err != nil {
			return nil, err
		}
	}
	keyRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return nil, err
	}
	return keyRing, nil
}

func loadMessage(file string) ([]byte, error) {
	armored, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	return armored, nil
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
	pgp := crypto.PGP()
	decHandle, _ := pgp.Decryption().
		DecryptionKeys(decryptionKeyRing).
		VerificationKeys(verificationKeyRing).
		VerifyTime(1557754627).
		New()
	verifyHandle, _ := pgp.Verify().
		VerificationKeys(verificationKeyRing).
		VerifyTime(1557754627).
		New()
	Decrypt(message, crypto.Armor, decHandle, verifyHandle, callbacks)
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
	sigErr := &crypto.SignatureVerificationError{}
	if errors.As(err, &sigErr) {
		return sigErr.Status
	}
	t.Errorf("Expected a signature verification error, got %v", err)
	return -1
}

func compareErrors(expected []crypto.SignatureVerificationError, actual []error, t *testing.T) {
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
	var expectedErrors = []crypto.SignatureVerificationError{newSignatureNotSigned(), newSignatureNotSigned()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{1}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNotSignedNoVerifier(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_12.asc")
	var expectedErrors = []crypto.SignatureVerificationError{newSignatureNotSigned(), newSignatureNoVerifier()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{2}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNotSignedFailed(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_13.asc")
	var expectedErrors = []crypto.SignatureVerificationError{newSignatureNotSigned(), newSignatureFailed(nil)}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{3}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierOk(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_20.asc")
	var expectedErrors = []crypto.SignatureVerificationError{}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{0}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierNotSigned(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_21.asc")
	var expectedErrors = []crypto.SignatureVerificationError{newSignatureNoVerifier(), newSignatureNotSigned()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{2}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierNoVerifier(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_22.asc")
	var expectedErrors = []crypto.SignatureVerificationError{newSignatureNoVerifier(), newSignatureNoVerifier()}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{2}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func TestMessageVerificationNoVerifierFailed(t *testing.T) {
	callbackResults := runScenario(t, "testdata/mime/scenario_23.asc")
	var expectedErrors = []crypto.SignatureVerificationError{newSignatureNoVerifier(), newSignatureFailed(nil)}
	compareErrors(expectedErrors, callbackResults.onError, t)
	expectedStatus := []int{3}
	compareStatus(expectedStatus, callbackResults.onVerified, t)
}

func readTestFile(name string, trimNewlines bool) string {
	data := string(readTestFileBytes(name))
	if trimNewlines {
		return strings.TrimRight(data, "\n")
	}
	return data
}

func readTestFileBytes(name string) []byte {
	data, err := ioutil.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return data
}
