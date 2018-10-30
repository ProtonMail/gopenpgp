package crypto

import (
	"time"
)

// UpdateTime update cached time
func (pm *PmCrypto) UpdateTime(newTime int64) {
	pm.latestServerTime = newTime
}

//GetTime get latest cached time
func (pm *PmCrypto) GetTime() int64 {
	return pm.getNow().Unix()
}

func (pm *PmCrypto) getNow() time.Time {
	if pm.latestServerTime > 0 {
		return time.Unix(pm.latestServerTime, 0)
	}

	return time.Now()
}

func (pm *PmCrypto) getTimeGenerator() func() time.Time {
	return func() time.Time {
		return pm.getNow()
	}
}
