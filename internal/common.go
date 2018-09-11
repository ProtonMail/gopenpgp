package internal

import (
	"regexp"
	"proton/pmcrypto/constants"
)


func TrimNewlines(input string) string {
	var re = regexp.MustCompile(`(?m)[ \t]*$`)
	return re.ReplaceAllString(input, "")
}

// Amount of seconds that a signature may be created after the verify time
// Consistent with the 2 day slack allowed in the ProtonMail Email Parser
const CreationTimeOffset = int64(60 * 60 * 24 * 2)

const (
	ARMOR_HEADER_VERSION = "Pmcrypto Golang 0.0.1 (" + constants.VERSION + ")"
	ARMOR_HEADER_COMMENT = "https://protonmail.com"
)
var ArmorHeaders = map[string]string {
	"Version": ARMOR_HEADER_VERSION,
	"Comment": ARMOR_HEADER_COMMENT,
}
