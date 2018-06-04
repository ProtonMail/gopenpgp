package pm

import (
	"time"
)

// UpdateTime update cached time
func (o *OpenPGP) UpdateTime(newTime int64) {
	o.lastestServerTime = newTime
}

//GetTime get latest cached time
func (o *OpenPGP) GetTime() int64 {
	return o.lastestServerTime
}

func (o *OpenPGP) getNow() time.Time {

	if o.lastestServerTime > 0 {
		tm := time.Unix(o.lastestServerTime, 0)
		return tm
	}

	return time.Now()
}
