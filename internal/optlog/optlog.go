// Package optlog contains ugly hacks to make debug logs allocate less when
// debug mode is not enabled.  Add all such hacks here to make sure that we keep
// track of them.
package optlog

import (
	"github.com/AdguardTeam/golibs/log"
)

// Debug1 is an ugly hack to prevent log.Debug from allocating.
func Debug1[T1 any](msg string, arg1 T1) {
	if log.GetLevel() >= log.DEBUG {
		log.Debug(msg, arg1)
	}
}

// Debug2 is an ugly hack to prevent log.Debug from allocating.
func Debug2[T1, T2 any](msg string, arg1 T1, arg2 T2) {
	if log.GetLevel() >= log.DEBUG {
		log.Debug(msg, arg1, arg2)
	}
}

// Debug3 is an ugly hack to prevent log.Debug from allocating.
func Debug3[T1, T2, T3 any](msg string, arg1 T1, arg2 T2, arg3 T3) {
	if log.GetLevel() >= log.DEBUG {
		log.Debug(msg, arg1, arg2, arg3)
	}
}

// Debug4 is an ugly hack to prevent log.Debug from allocating.
func Debug4[T1, T2, T3, T4 any](msg string, arg1 T1, arg2 T2, arg3 T3, arg4 T4) {
	if log.GetLevel() >= log.DEBUG {
		log.Debug(msg, arg1, arg2, arg3, arg4)
	}
}
