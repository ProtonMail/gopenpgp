package crypto

import (
	"time"
)

// UpdateTime update cached time
func (pm *PmCrypto) UpdateTime(newTime int64) {
	pm.latestServerTime = newTime
	pm.latestClientTime = time.Now()
}

//GetTime get latest cached time
func (pm *PmCrypto) GetTime() int64 {
	return pm.getNow().Unix()
}

func (pm *PmCrypto) getNow() time.Time {
	if pm.latestServerTime > 0 && !pm.latestClientTime.IsZero() {
		// Sub is monotome, it uses a monotime time clock in this case instead of the wall clock
		extrapolate := int64(pm.latestClientTime.Sub(time.Now()).Seconds())
		return time.Unix(pm.latestServerTime + extrapolate, 0)
	}

	return time.Now()
}

func (pm *PmCrypto) getTimeGenerator() func() time.Time {
	return func() time.Time {
		return pm.getNow()
	}
}
