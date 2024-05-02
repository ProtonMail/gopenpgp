package crypto

import (
	"time"
)

// UpdateTime updates cached time, new time has to be after previously set or will be ignored otherwise.
// Calling this function will cause time used in all crypto operations to be constant equal to provided.
func UpdateTime(newTime int64) {
	pgp.lock.Lock()
	defer pgp.lock.Unlock()

	if pgp.fixedTime < newTime {
		pgp.fixedTime = newTime
	}
}

// SetTimeOffset updates time offset used for crypto operations.
// Offset will be applied to all crypto operations unless fixed time is used.
func SetTimeOffset(newOffset int64) {
	pgp.lock.Lock()
	defer pgp.lock.Unlock()

	pgp.timeOffset = newOffset
}

// SetKeyGenerationOffset updates the offset when generating keys.
func SetKeyGenerationOffset(offset int64) {
	pgp.lock.Lock()
	defer pgp.lock.Unlock()

	pgp.generationOffset = offset
}

// GetUnixTime gets latest cached time.
func GetUnixTime() int64 {
	return GetTime().Unix()
}

// GetTime gets latest cached time.
func GetTime() time.Time {
	pgp.lock.RLock()
	defer pgp.lock.RUnlock()

	if pgp.fixedTime == 0 {
		return time.Unix(time.Now().Unix()+pgp.timeOffset, 0)
	}

	return time.Unix(pgp.fixedTime, 0)
}

// ----- INTERNAL FUNCTIONS -----

// setFixedTime sets fixed pgp time
func setFixedTime(newTime int64) {
	pgp.lock.Lock()
	defer pgp.lock.Unlock()

	pgp.fixedTime = newTime
}

// getKeyGenerationTime returns the current time with the key generation offset.
func getKeyGenerationTime() time.Time {
	pgp.lock.RLock()
	defer pgp.lock.RUnlock()

	if pgp.fixedTime == 0 {
		return time.Unix(time.Now().Unix()+pgp.generationOffset+pgp.timeOffset, 0)
	}

	return time.Unix(pgp.fixedTime+pgp.generationOffset, 0)
}
