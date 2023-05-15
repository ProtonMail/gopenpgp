// Package internal contains internal methods and constants.
package internal

import (
	"bytes"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/constants"
)

var nl []byte = []byte("\n")
var rnl []byte = []byte("\r\n")

func Canonicalize(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
}

func CanonicalizeBytes(text []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(text, rnl, nl), nl, rnl)
}

func TrimEachLine(text string) string {
	lines := strings.Split(text, "\n")

	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\r")
	}

	return strings.Join(lines, "\n")
}

func TrimEachLineBytes(text []byte) []byte {
	lines := bytes.Split(text, nl)

	for i := range lines {
		lines[i] = bytes.TrimRight(lines[i], " \t\r")
	}

	return bytes.Join(lines, nl)
}

// ArmorHeaders is a map of default armor headers.
var ArmorHeaders = map[string]string{
	"Version": constants.ArmorHeaderVersion,
	"Comment": constants.ArmorHeaderComment,
}
