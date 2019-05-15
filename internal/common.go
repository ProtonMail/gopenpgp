// Package internal contains internal methods and constants.
package internal

import (
	"regexp"

	"github.com/ProtonMail/gopenpgp/constants"
)

// TrimNewlines removes whitespace from the end of each line of the input
// string.
func TrimNewlines(input string) string {
	var re = regexp.MustCompile(`(?m)[ \t]*$`)
	return re.ReplaceAllString(input, "")
}

// CreationTimeOffset stores the amount of seconds that a signature may be
// created in the future, to compensate for clock skew.
const CreationTimeOffset = int64(60 * 60 * 24 * 2)

// ArmorHeaders is a map of default armor headers.
var ArmorHeaders = map[string]string{
	"Version": constants.ArmorHeaderVersion,
	"Comment": constants.ArmorHeaderComment,
}
