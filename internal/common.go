package internal

import (
	"regexp"

	"github.com/ProtonMail/gopenpgp/constants"
)

// TrimNewlines removes a whitespace in the end of string (don't stop on linebreak)
func TrimNewlines(input string) string {
	var re = regexp.MustCompile(`(?m)[ \t]*$`)
	return re.ReplaceAllString(input, "")
}

// CreationTimeOffset stores the amount of seconds that a signature may be
// created in the future, to compensate for clock skew
const CreationTimeOffset = int64(60 * 60 * 24 * 2)

// ArmorHeaders from gopenpgp
var ArmorHeaders = map[string]string{
	"Version": constants.ArmorHeaderVersion,
	"Comment": constants.ArmorHeaderComment,
}
