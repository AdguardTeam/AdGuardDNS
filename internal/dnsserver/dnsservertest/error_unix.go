//go:build unix

package dnsservertest

import (
	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/sys/unix"
)

// errorIsAddrInUse returns true if err is an address already in use error.
func errorIsAddrInUse(err error) (ok bool) {
	return errors.Is(err, unix.EADDRINUSE)
}
