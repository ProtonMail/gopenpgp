package crypto

import (
	"time"
)

type Clock func() time.Time

func NewConstantClock(unixTime int64) Clock {
	return func() time.Time {
		return time.Unix(unixTime, 0)
	}
}

func ZeroClock() Clock {
	return func() time.Time {
		return time.Time{}
	}
}
