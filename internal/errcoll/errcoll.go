package errcoll

import (
	"fmt"
	"runtime"
)

// Common Functionality

// caller returns the caller position using the appropriate depth.
func caller(depth int) (callerPos string) {
	callerPos = "<position unknown>"
	_, callerFile, callerLine, ok := runtime.Caller(depth)
	if ok {
		callerPos = fmt.Sprintf("%s:%d", callerFile, callerLine)
	}

	return callerPos
}
