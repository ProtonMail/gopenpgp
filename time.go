package pm

import (
	"time"
)

// UpdateTime update cached time
func (o *OpenPGP) UpdateTime(newTime int64) {
	o.latestServerTime = newTime
}

//GetTime get latest cached time
func (o *OpenPGP) GetTime() int64 {
	return o.latestServerTime
}

func (o *OpenPGP) getNow() time.Time {

	if o.latestServerTime > 0 {
		return time.Unix(o.latestServerTime, 0)
	}

	return time.Now()
}
