// Package crypto provides a high-level API for common OpenPGP functionality.
package crypto

import "time"

// GopenPGP is used as a "namespace" for many of the functions in this package.
// It is a struct that keeps track of time skew between server and client.
type GopenPGP struct {
	latestServerTime int64
	latestClientTime time.Time
}

var pgp *GopenPGP = nil

// GopenPGPFactory creates the GopenPGP object, initializing time
func GopenPGPFactory(newTime int64) *GopenPGP {
	pgp = &GopenPGP {
		latestServerTime: newTime,
		latestClientTime: time.Now(),
	}
	
	return pgp
}
