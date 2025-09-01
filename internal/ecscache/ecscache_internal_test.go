package ecscache

import (
	"math"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
)

// isSafeFloatInt returns true if d can be safely represented inside a float64.
func isSafeFloatInt(d time.Duration) (ok bool) {
	const (
		maxSafeFloatInt = 1<<53 - 1
		minSafeFloatInt = -maxSafeFloatInt
	)

	return d > minSafeFloatInt && d < maxSafeFloatInt
}

func TestRoundDiv(t *testing.T) {
	roundDivCheck := func(a, b time.Duration) (res time.Duration) {
		if !isSafeFloatInt(a) || !isSafeFloatInt(b) {
			return 0
		}

		return roundDiv(a, b)
	}

	mathRoundCheck := func(a, b time.Duration) (res time.Duration) {
		if !isSafeFloatInt(a) || !isSafeFloatInt(b) {
			return 0
		}

		return time.Duration(math.Round(float64(a) / float64(b)))
	}

	assert.NoError(t, quick.CheckEqual(roundDivCheck, mathRoundCheck, &quick.Config{
		MaxCount: 100_000,
	}))
}
