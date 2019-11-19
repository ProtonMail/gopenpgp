package crypto

import (
	"io/ioutil"
	"strings"
)

var err error

func readTestFile(name string, trimNewlines bool) string {
	data, err := ioutil.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	if trimNewlines {
		return strings.TrimRight(string(data), "\n")
	}
	return string(data)
}

func init() {
	UpdateTime(1557754627) // 2019-05-13T13:37:07+00:00

	initGenerateKeys()
	initArmoredKeys()
	initKeyRings()
}