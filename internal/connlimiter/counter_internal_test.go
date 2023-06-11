package connlimiter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCounter(t *testing.T) {
	t.Run("same", func(t *testing.T) {
		c := &counter{
			current:     0,
			stop:        1,
			resume:      1,
			isAccepting: true,
		}

		assert.True(t, c.increment())
		assert.False(t, c.increment())

		c.decrement()
		assert.True(t, c.increment())
		assert.False(t, c.increment())
	})

	t.Run("more", func(t *testing.T) {
		c := &counter{
			current:     0,
			stop:        2,
			resume:      1,
			isAccepting: true,
		}

		assert.True(t, c.increment())
		assert.True(t, c.increment())
		assert.False(t, c.increment())

		c.decrement()
		assert.True(t, c.increment())
		assert.False(t, c.increment())
	})
}
