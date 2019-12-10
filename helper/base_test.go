package helper

import (
	"io/ioutil"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

const testTime = 1557754627 // 2019-05-13T13:37:07+00:00

func readTestFile(name string, trimNewlines bool) string {
	data, err := ioutil.ReadFile("../crypto/testdata/" + name) //nolint
	if err != nil {
		panic(err)
	}
	if trimNewlines {
		return strings.TrimRight(string(data), "\n")
	}
	return string(data)
}

// Corresponding key in ../crypto/testdata/keyring_privateKey
var testMailboxPassword = []byte("apple")

func init() {
	crypto.UpdateTime(testTime) // 2019-05-13T13:37:07+00:00
}
