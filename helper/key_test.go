package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSHA256FingerprintsV4(t *testing.T) {
	sha256Fingerprints, err := GetSHA256Fingerprints(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Cannot unarmor key:", err)
	}

	assert.Len(t, sha256Fingerprints, 2)
	assert.Exactly(t, "d9ac0b857da6d2c8be985b251a9e3db31e7a1d2d832d1f07ebe838a9edce9c24", sha256Fingerprints[0])
	assert.Exactly(t, "203dfba1f8442c17e59214d9cd11985bfc5cc8721bb4a71740dd5507e58a1a0d", sha256Fingerprints[1])
}
