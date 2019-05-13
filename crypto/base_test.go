package crypto

import (
	"io/ioutil"
)

var err error

func readTestFile(name string) string {
	data, err := ioutil.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return string(data)
}
