package crypto

import (
	"time"
)

// UpdateTime updates cached time.
func UpdateTime(newTime int64) {
	if newTime > pgp.latestServerTime {
		pgp.latestServerTime = newTime
		pgp.latestClientTime = time.Now()
	}
}

// SetKeyGenerationOffset updates the offset when generating keys.
func SetKeyGenerationOffset(offset int64) {
	pgp.generationOffset = offset
}

// GetUnixTime gets latest cached time.
func GetUnixTime() int64 {
	return getNow().Unix()
}

// GetTime gets latest cached time.
func GetTime() time.Time {
	return getNow()
}

// ----- INTERNAL FUNCTIONS -----

// getNow returns the latest server time.
func getNow() time.Time {
	if pgp.latestServerTime == 0 {
		return time.Now()
	}

	return time.Unix(pgp.latestServerTime, 0)
}

// getTimeGenerator Returns a time generator function.
func getTimeGenerator() func() time.Time {
	return getNow
}

// getNowKeyGenerationOffset returns the current time with the key generation offset.
func getNowKeyGenerationOffset() time.Time {
	if pgp.latestServerTime == 0 {
		return time.Unix(time.Now().Unix()+pgp.generationOffset, 0)
	}

	return time.Unix(pgp.latestServerTime+pgp.generationOffset, 0)
}

// getKeyGenerationTimeGenerator Returns a time generator function with the key generation offset.
func getKeyGenerationTimeGenerator() func() time.Time {
	return getNowKeyGenerationOffset
}
