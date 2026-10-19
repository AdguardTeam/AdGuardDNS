//go:build linux

package bindtodevice

import (
	"sync"
	"time"
)

// dynamicDeadline represents a deadline that can change.  Such changes are
// broadcast to all dependent listeners.
//
// Inspired by pipeDeadline in package net.
//
// TODO(a.garipov): Consider a new testable API for [time.Timer] values.
type dynamicDeadline struct {
	// mu protects all fields below.  It is a simple mutex as opposed to a RW
	// one, since read and write frequency is assumed to be basically the same.
	mu *sync.Mutex

	// timer is set dynamically using [time.AfterFunc].
	timer *time.Timer

	// value is the last set deadline value.
	value time.Time

	// cancel is closed when the deadline is exceeded.  It must not be nil and
	// must not be sent to.
	cancel chan unit
}

// newDynamicDeadline creates a new dynamically-changeable deadline.
func newDynamicDeadline() (d *dynamicDeadline) {
	return &dynamicDeadline{
		mu:     &sync.Mutex{},
		cancel: make(chan unit),
	}
}

// set sets the deadline.  On a timeout, the channel returned by wait is closed.
// d may be expired.  A zero value for dl prevents timeout.
func (d *dynamicDeadline) set(dl time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.value = dl

	if d.timer != nil && !d.timer.Stop() {
		// Wait for the timer callback to finish closing the cancel.
		<-d.cancel
	}

	d.timer = nil
	closed := d.isCanceled()

	if dl.IsZero() {
		if closed {
			d.cancel = make(chan unit)
		}

		return
	}

	// Time in the future, setup a timer to cancel in the future.
	if dur := time.Until(dl); dur > 0 {
		if closed {
			d.cancel = make(chan unit)
		}

		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})

		return
	}

	// Time in the past, so close immediately.
	if !closed {
		close(d.cancel)
	}
}

// isCanceled returns true if d.cancel is closed.  d.mu must be locked.
func (d *dynamicDeadline) isCanceled() (ok bool) {
	select {
	case <-d.cancel:
		return true
	default:
		return false
	}
}

// wait returns a channel that is closed when the deadline is exceeded and the
// deadline at the time of call.
func (d *dynamicDeadline) wait() (cancel <-chan unit, dl time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.cancel, d.value
}
