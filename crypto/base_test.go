package crypto

import (
	"io/ioutil"
	"strings"
	"time"
)

var err error

var _ = GopenPGPFactory(time.Now().Unix())

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
