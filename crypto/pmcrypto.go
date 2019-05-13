// Package crypto contains all methods and classes needed for manipulation
// with underlying cryptographic operations. It uses low-level openpgp functions
// and provides higher level views. It uses models of messages, attachments
// and other higher-level entities
package crypto

import "time"

// PmCrypto structure is used to manage server time shift. It should be also used for any
// other specific general cryptographic entities.
type PmCrypto struct {
	//latestServerTime unix time cache
	latestServerTime int64
	latestClientTime time.Time
}
