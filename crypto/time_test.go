package crypto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTime(t *testing.T) {
	UpdateTime(1571072494)
	time.Sleep(1 * time.Second)
	now := GetUnixTime()

	assert.Exactly(t, int64(1571072494), now) // Use latest server time
	UpdateTime(testTime)
}
