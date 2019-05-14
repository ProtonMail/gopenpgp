package crypto

import (
	"time"
)

var pmCrypto = PmCrypto{}

// GetPmCrypto return global PmCrypto
func GetPmCrypto() *PmCrypto {
	return &pmCrypto
}

// UpdateTime updates cached time
func (pm *PmCrypto) UpdateTime(newTime int64) {
	pm.latestServerTime = newTime
	pm.latestClientTime = time.Now()
}

// GetTimeUnix gets latest cached time
func (pm *PmCrypto) GetTimeUnix() int64 {
	return pm.getNow().Unix()
}

// GetTime gets latest cached time
func (pm *PmCrypto) GetTime() time.Time {
	return pm.getNow()
}

func (pm *PmCrypto) getNow() time.Time {
	if pm.latestServerTime > 0 && !pm.latestClientTime.IsZero() {
		// Until is monotonic, it uses a monotonic clock in this case instead of the wall clock
		extrapolate := int64(time.Until(pm.latestClientTime).Seconds())
		return time.Unix(pm.latestServerTime+extrapolate, 0)
	}

	return time.Now()
}

func (pm *PmCrypto) getTimeGenerator() func() time.Time {
	return func() time.Time {
		return pm.getNow()
	}
}
