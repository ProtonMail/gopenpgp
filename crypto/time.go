package crypto

import (
	"errors"
	"time"
)

// UpdateTime updates cached time
func UpdateTime(newTime int64) {
	pgp.latestServerTime = newTime
	pgp.latestClientTime = time.Now()
}

// GetUnixTime gets latest cached time
func GetUnixTime() int64 {
	return getNow().Unix()
}

// GetTime gets latest cached time
func GetTime() time.Time {
	return getNow()
}

// ----- INTERNAL FUNCTIONS -----

// getNow returns current time
func getNow() time.Time {
	extrapolate, err := getDiff()

	if err != nil {
		return time.Now()
	}

	return time.Unix(pgp.latestServerTime+extrapolate, 0)
}

func getDiff() (int64, error) {
	if pgp.latestServerTime > 0 && !pgp.latestClientTime.IsZero() {
		// Since is monotonic, it uses a monotonic clock in this case instead of the wall clock
		return int64(time.Since(pgp.latestClientTime).Seconds()), nil
	}

	return 0, errors.New("gopenpgp: latest server time not available")
}

// getTimeGenerator Returns a time generator function
func getTimeGenerator() func() time.Time {
	return getNow
}
