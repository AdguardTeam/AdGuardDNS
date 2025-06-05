package profiledb

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
)

// ErrDeviceNotFound is an error returned by lookup methods when a device
// couldn't be found.
const ErrDeviceNotFound errors.Error = "device not found"

// ErrProfileNotFound is an error returned by lookup methods when a profile
// couldn't be found.
const ErrProfileNotFound errors.Error = "profile not found"

// AuthenticationFailedError is returned by methods of [Storage] when the
// authentication to the storage fails.
type AuthenticationFailedError struct {
	Message string
}

// type check
var _ error = (*AuthenticationFailedError)(nil)

// Error implements the [error] interface for *AuthenticationFailedError.
func (err *AuthenticationFailedError) Error() (msg string) {
	return err.Message
}

// BadRequestError is returned by methods of [Storage] when the request is
// malformed.
type BadRequestError struct {
	Message string
}

// type check
var _ error = (*BadRequestError)(nil)

// Error implements the [error] interface for *BadRequestError.
func (err *BadRequestError) Error() (msg string) {
	return err.Message
}

// DeviceQuotaExceededError is returned by [Storage.CreateAutoDevice] when the
// profile has exceeded the number of devices it can create.
type DeviceQuotaExceededError struct {
	Message string
}

// type check
var _ error = (*DeviceQuotaExceededError)(nil)

// Error implements the [error] interface for *DeviceQuotaExceededError.
func (err *DeviceQuotaExceededError) Error() (msg string) {
	return err.Message
}

// type check
var _ errcoll.SentryReportableError = (*DeviceQuotaExceededError)(nil)

// IsSentryReportable implements the [errcoll.SentryReportableError] interface
// for *DeviceQuotaExceededError.
func (err *DeviceQuotaExceededError) IsSentryReportable() (ok bool) { return false }

// RateLimitedError is returned by methods of [Storage] when the requests are
// made too often.
type RateLimitedError struct {
	// Message is the error message from the storage.
	Message string

	// RetryDelay is the hint to use for when to retry the request.
	//
	// TODO(a.garipov):  Use in [Default.Refresh].
	RetryDelay time.Duration
}

// type check
var _ error = (*RateLimitedError)(nil)

// Error implements the [error] interface for *RateLimitedError.
func (err *RateLimitedError) Error() (msg string) {
	return fmt.Sprintf("rate limited: %s; retry in %s", err.Message, err.RetryDelay)
}
