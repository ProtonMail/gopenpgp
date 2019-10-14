package crypto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTime(t *testing.T) {
	pgp.UpdateTime(1571072494)
	time.Sleep(1 * time.Second)
	diff, err := pgp.getDiff()

	if err != nil {
		t.Fatal("Expected no error when calculating time difference, got:", err)
	}
	assert.Exactly(t, int64(1), diff)

	pgp.UpdateTime(testTime)
}
