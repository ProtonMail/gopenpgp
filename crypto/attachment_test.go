package crypto

import (
	//	"bytes"
	"encoding/base64"
	//	"io/ioutil"
	"reflect"
	"strings"
	"testing"
)

var testKeyPackets = "wcBMA0fcZ7XLgmf2AQgAiRsOlnm1kSB4/lr7tYe6pBsRGn10GqwUhrwU5PMKOHdCgnO12jO3y3CzP0Yl/jGhAYja9wLDqH8X0sk3tY32u4Sb1Qe5IuzggAiCa4dwOJj5gEFMTHMzjIMPHR7A70XqUxMhmILye8V4KRm/j4c1sxbzA1rM3lYBumQuB5l/ck0Kgt4ZqxHVXHK5Q1l65FHhSXRj8qnunasHa30TYNzP8nmBA8BinnJxpiQ7FGc2umnUhgkFt    jm5ixu9vyjr9ukwDTbwAXXfmY+o7tK7kqIXJcmTL6k2UeC6Mz1AagQtRCRtU+bv/3zGojq/trZo9lom3naIeQYa36Ketmcpj2Qwjg=="

const testAttachmentCleartext = `cc,
dille.
`

const testAttachmentEncrypted = `0ksB0fHC6Duezx/0TqpK/82HSl8+qCY0c2BCuyrSFoj6Dubd93T3//32jVYa624NYvfvxX+UxFKYKJxG09gFsU1IVc87cWvUgmUmgjU=`

func TestAttachment_GetKey(t *testing.T) {
	split, err := SeparateKeyAndData(testPrivateKeyRing, strings.NewReader(testKeyPackets), len(testKeyPackets), -1)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	if !reflect.DeepEqual(testSymmetricKey, split.KeyPacket) {
		t.Fatalf("Invalid attachment key: expected %+v, got %+v", testSymmetricKey, split.KeyPacket)
	}
}

func TestAttachment_SetKey(t *testing.T) {

	var packets string
	var err error

	if packets, err = SetKey(testPublicKeyRing, testSymmetricKey); err != nil {
		t.Fatal("Expected no error while encrypting attachment key, got:", err)
	}
	keyPackets := packets

	split, err := SeparateKeyAndData(testPrivateKeyRing, strings.NewReader(keyPackets), len(keyPackets), -1)
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment key, got:", err)
	}

	if !reflect.DeepEqual(testSymmetricKey, split.KeyPacket) {
		t.Fatalf("Invalid attachment key: expected %+v, got %+v", testSymmetricKey, split.KeyPacket)
	}
}

func TestAttachnent_EncryptDecrypt(t *testing.T) {
	plainData, _ := base64.StdEncoding.DecodeString(testAttachmentCleartext)

	var pmCrypto = PmCrypto{}

	encSplit, err := pmCrypto.EncryptAttachment(plainData, "s.txt", testPrivateKeyRing)
	if err != nil {
		t.Fatal("Expected no error while encrypting attachment, got:", err)
	}

	redecData, err := pmCrypto.DecryptAttachment(encSplit.KeyPacket, encSplit.DataPacket, testPrivateKeyRing, "")
	if err != nil {
		t.Fatal("Expected no error while decrypting attachment, got:", err)
	}

	s := string(redecData)

	if testAttachmentCleartext != s {
		t.Fatalf("Invalid decrypted attachment: expected %v, got %v", testAttachmentCleartext, s)
	}

}
