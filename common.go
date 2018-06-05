package pm

import (
	"regexp"
)

var armorHeader = map[string]string{
	"Version": "OpenPGP Golang 0.0.1 (" + Version() + ")",
	"Comment": "https://protonmail.com",
}

// Key ... add later
// protonmail key object
type Key struct {
	KeyID       string
	PublicKey   string
	PrivateKey  string
	FingerPrint string
}

//Address ... add later protonmail address object
type Address struct {
	// address_id : string;
	// #optional
	// address_name : string;
	keys []Key
}

func trimNewlines(input string) string {
	var re = regexp.MustCompile(`(?m)[ \t]*$`)
	return re.ReplaceAllString(input, "")
}
