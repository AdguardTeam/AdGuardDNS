// Package bindtodevice contains an implementation of the [netext.ListenConfig]
// interface that uses Linux's SO_BINDTODEVICE socket option to be able to bind
// to a device.
package bindtodevice

import (
	"fmt"
	"net"
)

// ID is the unique identifier of an interface listener.
type ID string

// unit is a convenient alias for struct{}.
type unit = struct{}

// Convenient constants containing type names for error reporting using
// [wrapConnError].
const (
	tnChanPConn = "chanPacketConn"
	tnChanLsnr  = "chanListener"
)

// wrapConnError is a helper for creating informative errors.
func wrapConnError(typeName, methodName string, laddr net.Addr, err error) (wrapped error) {
	return fmt.Errorf("bindtodevice: %s %s: %s: %w", typeName, laddr, methodName, err)
}
