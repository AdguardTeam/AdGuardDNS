// Package billstat implements the AdGuard DNS billing statistics database.
package billstat

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Common Constants, Types, And Utilities

// Recorder is the billing statistics recorder interface.
type Recorder interface {
	Record(
		ctx context.Context,
		id agd.DeviceID,
		ctry agd.Country,
		asn agd.ASN,
		start time.Time,
		proto agd.Protocol,
	)
}

// type check
var _ Recorder = EmptyRecorder{}

// EmptyRecorder is a billing statistics recorder that does nothing.
type EmptyRecorder struct{}

// Record implements the Recorder interface for EmptyRecorder.
func (EmptyRecorder) Record(
	_ context.Context,
	_ agd.DeviceID,
	_ agd.Country,
	_ agd.ASN,
	_ time.Time,
	_ agd.Protocol,
) {
}

// Uploader is the interface for a backend that accepts the billing statistics
// records.
type Uploader interface {
	Upload(ctx context.Context, records Records) (err error)
}

// Record is a single billing statistics Record.
type Record struct {
	// Time is the time of the most recent query from the device.
	Time time.Time

	// Country is the detected country of the client's IP address, if any.
	Country agd.Country

	// ASN is the detected ASN of the client's IP address, if any.
	ASN agd.ASN

	// Queries is the total number of Queries the device has performed since the
	// most recent sync.  This value is an int32 to be in sync with the business
	// logic backend which uses this type.  Change it if it is changed there.
	Queries int32

	// Proto is the DNS protocol of the most recent query from the device.
	Proto agd.Protocol
}

// Records is a helpful alias for a mapping of devices to their billing
// statistics records.
type Records = map[agd.DeviceID]*Record
