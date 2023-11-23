package crypto

import (
	"time"
)

// Clock is a function that returns a timestamp.
type Clock func() time.Time

// NewConstantClock returns a Clock, which always returns unixTime.
func NewConstantClock(unixTime int64) Clock {
	return func() time.Time {
		return time.Unix(unixTime, 0)
	}
}

// ZeroClock returns a Clock, which always returns the zero time.Time.
func ZeroClock() Clock {
	return func() time.Time {
		return time.Time{}
	}
}
