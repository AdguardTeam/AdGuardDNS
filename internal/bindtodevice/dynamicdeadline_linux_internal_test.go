//go:build linux

package bindtodevice

import (
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicDeadline(t *testing.T) {
	t.Parallel()

	t.Run("initial", func(t *testing.T) {
		t.Parallel()

		d := newDynamicDeadline()
		_, deadline := d.wait()

		d.mu.Lock()
		defer d.mu.Unlock()

		assert.False(t, d.isCanceled())
		assert.Zero(t, deadline)
	})

	t.Run("common", func(t *testing.T) {
		t.Parallel()

		d := newDynamicDeadline()
		wantDeadline := time.Now().Add(testTimeout / 3)
		d.set(wantDeadline)

		cancel, deadline := d.wait()
		assert.Equal(t, wantDeadline, deadline)

		_, ok := testutil.RequireReceive(t, cancel, testTimeout)
		require.False(t, ok)

		d.mu.Lock()
		defer d.mu.Unlock()

		assert.True(t, d.isCanceled())
	})

	t.Run("deadline_in_past", func(t *testing.T) {
		t.Parallel()

		d := newDynamicDeadline()
		pastDeadline := time.Now().Add(-time.Hour)
		d.set(pastDeadline)

		func() {
			d.mu.Lock()
			defer d.mu.Unlock()

			assert.True(t, d.isCanceled())
		}()

		cancel, deadline := d.wait()
		assert.Equal(t, pastDeadline, deadline)

		_, ok := testutil.RequireReceive(t, cancel, testTimeout)
		require.False(t, ok)
	})

	t.Run("reset_deadline", func(t *testing.T) {
		t.Parallel()

		d := newDynamicDeadline()
		pastDeadline := time.Now().Add(-time.Hour)
		d.set(pastDeadline)
		pastCancel, _ := d.wait()

		futureDeadline := time.Now().Add(time.Hour)
		d.set(futureDeadline)
		futureCancel, deadline := d.wait()
		assert.NotEqual(t, pastCancel, futureCancel)
		assert.Equal(t, futureDeadline, deadline)

		d.set(time.Time{})
		cancel, deadline := d.wait()
		assert.Equal(t, futureCancel, cancel)
		assert.Zero(t, deadline)

		d.mu.Lock()
		defer d.mu.Unlock()

		assert.False(t, d.isCanceled())
	})
}
