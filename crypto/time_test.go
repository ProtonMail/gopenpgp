package crypto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_setFixedTime(t *testing.T) {
	defer setFixedTime(testTime)
	setFixedTime(1571072494)
	time.Sleep(1 * time.Second)
	now := GetUnixTime()

	assert.Exactly(t, int64(1571072494), now) // Use fixed time
}

func Test_UpdateTime(t *testing.T) {
	defer setFixedTime(testTime)
	UpdateTime(1571072494)
	time.Sleep(1 * time.Second)
	now := GetUnixTime()

	assert.Exactly(t, int64(1571072494), now) // Use fixed time

	UpdateTime(1571072490)
	now = GetUnixTime()

	assert.Exactly(t, int64(1571072494), now) // Use previous fixed time, ignoring time before previous

	UpdateTime(1571072495)
	now = GetUnixTime()

	assert.Exactly(t, int64(1571072495), now) // Use updated fixed time
}

func Test_TimeOffset(t *testing.T) {
	defer setFixedTime(testTime)
	defer SetTimeOffset(0)
	setFixedTime(testTime)
	SetTimeOffset(30)
	time.Sleep(1 * time.Second)
	now := GetUnixTime()

	assert.Exactly(t, int64(testTime), now) // Use fixed time without offset

	setFixedTime(0)
	SetTimeOffset(0)
	now = GetUnixTime()
	SetTimeOffset(30)

	assert.GreaterOrEqual(t, GetUnixTime(), now+30) // Use offset with no fixed time
}
