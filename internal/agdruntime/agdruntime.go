// Package agdruntime contains runtime-related utilities.
package agdruntime

import (
	"runtime"
)

// Manager represents a runtime threads helper.
//
// TODO(a.garipov):  Consider moving to golibs.
type Manager interface {
	// TerminateThread kills an OS thread.  It is intended to be called in a
	// goroutine.  It must be safe for concurrent use.
	TerminateThread()

	// ThreadsCount returns the number of OS threads used by the current
	// process.
	ThreadsCount() (count uint)
}

// Empty implements the [Manager] interface that does nothing.
type Empty struct{}

// type check
var _ Manager = Empty{}

// TerminateThread implements the [Manager] interface for Empty.
func (Empty) TerminateThread() {}

// ThreadsCount implements the [Manager] interface for Empty.  It always returns
// 1.
func (Empty) ThreadsCount() (count uint) {
	return 1
}

// System is a default implementation of threads management interface.
type System struct{}

// type check
var _ Manager = System{}

// TerminateThread implements the [Manager] interface for System.
//
// TODO(a.garipov):  Consider adding logs.
func (System) TerminateThread() {
	// Exiting WITHOUT calling [runtime.UnlockOSThread] forces the Go runtime to
	// terminate the host OS thread.
	//
	// See https://github.com/golang/go/issues/14592.
	runtime.LockOSThread()
}

// ThreadsCount implements the [Manager] interface for System.
func (System) ThreadsCount() (count uint) {
	threadCount, _ := runtime.ThreadCreateProfile(nil)

	return uint(threadCount)
}
