package devicesetter

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
)

const (
	// ErrUnknownDedicated is returned by [Interface.SetDevice] if the request
	// should be dropped, because it's a request for an unknown dedicated IP
	// address.
	ErrUnknownDedicated errors.Error = "unknown dedicated ip"
)

// deviceIDError is an error about bad device ID or other issues found during
// device ID checking.
type deviceIDError struct {
	err error
	typ string
}

// type check
var _ error = (*deviceIDError)(nil)

// newDeviceIDError is a helper constructor for device-ID errors.
func newDeviceIDError(orig error, typ string) (err error) {
	return &deviceIDError{
		err: orig,
		typ: typ,
	}
}

// Error implements the error interface for *deviceIDError.
func (err *deviceIDError) Error() (msg string) {
	return fmt.Sprintf("%s device id check: %s", err.typ, err.err)
}

// type check
var _ errors.Wrapper = (*deviceIDError)(nil)

// Unwrap implements the [errors.Wrapper] interface for *deviceIDError.
func (err *deviceIDError) Unwrap() (unwrapped error) { return err.err }

// type check
var _ errcoll.SentryReportableError = (*deviceIDError)(nil)

// IsSentryReportable implements the [errcoll.SentryReportableError] interface
// for *deviceIDError.
func (*deviceIDError) IsSentryReportable() (ok bool) { return false }
