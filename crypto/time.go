package crypto

import (
	"time"
)

var pgp = GopenPGP{}

// GetGopenPGP return global GopenPGP
func GetGopenPGP() *GopenPGP {
	return &pgp
}

// UpdateTime updates cached time
func (pgp *GopenPGP) UpdateTime(newTime int64) {
	pgp.latestServerTime = newTime
	pgp.latestClientTime = time.Now()
}

// GetUnixTime gets latest cached time
func (pgp *GopenPGP) GetUnixTime() int64 {
	return pgp.getNow().Unix()
}

// GetTime gets latest cached time
func (pgp *GopenPGP) GetTime() time.Time {
	return pgp.getNow()
}

// ----- INTERNAL FUNCTIONS -----

// getNow returns current time
func (pgp *GopenPGP) getNow() time.Time {
	if pgp.latestServerTime > 0 && !pgp.latestClientTime.IsZero() {
		// Until is monotonic, it uses a monotonic clock in this case instead of the wall clock
		extrapolate := int64(time.Until(pgp.latestClientTime).Seconds())
		return time.Unix(pgp.latestServerTime+extrapolate, 0)
	}

	return time.Now()
}

// getTimeGenerator Returns a time generator function
func (pgp *GopenPGP) getTimeGenerator() func() time.Time {
	return func() time.Time {
		return pgp.getNow()
	}
}
