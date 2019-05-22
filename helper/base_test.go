package helper

import (
	"io/ioutil"
	"strings"
)

var err error

func readTestFile(name string, trimNewlines bool) string {
	data, err := ioutil.ReadFile("../crypto/testdata/" + name)
	if err != nil {
		panic(err)
	}
	if trimNewlines {
		return strings.TrimRight(string(data), "\n")
	}
	return string(data)
}

// Corresponding key in ../crypto/testdata/keyring_privateKey
const testMailboxPassword = "apple"
