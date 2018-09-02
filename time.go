package pmcrypto

import (
	"time"
)

// UpdateTime update cached time
func (o *OpenPGP) UpdateTime(newTime int64) {
	o.latestServerTime = newTime
	o.latestClientTime = time.Now()
}

//GetTime get latest cached time
func (o *OpenPGP) GetTime() int64 {
	return o.getNow().Unix()
}

func (o *OpenPGP) getNow() time.Time {
	if o.latestServerTime > 0 && !o.latestClientTime.IsZero() {
		// Sub is monotome, it uses a monotime time clock in this case instead of the wall clock
		extrapolate := int64(o.latestClientTime.Sub(time.Now()).Seconds())
		return time.Unix(o.latestServerTime + extrapolate, 0)
	}

	return time.Now()
}

func (o *OpenPGP) getTimeGenerator() func() time.Time {
	return func() time.Time {
		return o.getNow()
	}
}
