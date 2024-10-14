package billstat

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
)

// RuntimeRecorderConfig is the configuration structure for a runtime billing
// statistics recorder.  All fields must be non-empty.
type RuntimeRecorderConfig struct {
	// Logger is used for logging the operation of the recorder.
	Logger *slog.Logger

	// ErrColl is used to collect errors during refreshes.
	ErrColl errcoll.Interface

	// Uploader is used to upload the billing statistics records to.
	Uploader Uploader

	// Metrics is used for the collection of the billing statistics.
	Metrics Metrics
}

// NewRuntimeRecorder creates a new runtime billing statistics database.  c must
// be non-nil.
func NewRuntimeRecorder(c *RuntimeRecorderConfig) (r *RuntimeRecorder) {
	return &RuntimeRecorder{
		logger:   c.Logger,
		mu:       &sync.Mutex{},
		records:  Records{},
		uploader: c.Uploader,
		errColl:  c.ErrColl,
		metrics:  c.Metrics,
	}
}

// RuntimeRecorder is the runtime billing statistics recorder.  The records kept
// here are not persistent.
type RuntimeRecorder struct {
	logger *slog.Logger

	// mu protects records and syncTime.
	mu *sync.Mutex

	// records are the statistics records awaiting their synchronization.
	records Records

	// uploader is the uploader to which the billing statistics records are
	// uploaded.
	uploader Uploader

	// errColl is used to collect errors during refreshes.
	errColl errcoll.Interface

	// metrics is used for the collection of the billing statistics.
	metrics Metrics
}

// type check
var _ Recorder = (*RuntimeRecorder)(nil)

// Record implements the Recorder interface for *RuntimeRecorder.
func (r *RuntimeRecorder) Record(
	ctx context.Context,
	id agd.DeviceID,
	ctry geoip.Country,
	asn geoip.ASN,
	start time.Time,
	proto agd.Protocol,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := r.records[id]
	if rec == nil {
		r.records[id] = &Record{
			Time:    start,
			Country: ctry,
			ASN:     asn,
			Queries: 1,
			Proto:   proto,
		}

		r.metrics.BufferSizeSet(ctx, float64(len(r.records)))
	} else {
		rec.Time = start
		rec.Country = ctry
		rec.ASN = asn
		rec.Queries++
		rec.Proto = proto
	}
}

// type check
var _ agdservice.Refresher = (*RuntimeRecorder)(nil)

// Refresh implements the [agdserivce.Refresher] interface for *RuntimeRecorder.
// It uploads the currently available data and resets it.
func (r *RuntimeRecorder) Refresh(ctx context.Context) (err error) {
	r.logger.DebugContext(ctx, "refresh started")
	defer r.logger.DebugContext(ctx, "refresh finished")

	records := r.resetRecords(ctx)

	startTime := time.Now()
	defer func() {
		dur := time.Since(startTime).Seconds()

		isSuccess := err == nil
		if !isSuccess {
			r.remergeRecords(ctx, records)
			r.logger.WarnContext(ctx, "refresh failed, records remerged")
		}

		r.metrics.HandleUploadDuration(ctx, dur, isSuccess)
	}()

	err = r.uploader.Upload(ctx, records)
	if err != nil {
		errcoll.Collect(ctx, r.errColl, r.logger, "uploading billstat", err)
	}

	return err
}

// resetRecords returns the current data and resets the records map to an empty
// map.
func (r *RuntimeRecorder) resetRecords(ctx context.Context) (records Records) {
	r.mu.Lock()
	defer r.mu.Unlock()

	records, r.records = r.records, Records{}

	r.metrics.BufferSizeSet(ctx, 0)

	return records
}

// remergeRecords merges records back into the database, unless there is already
// a newer record, in which case it merges the results.
func (r *RuntimeRecorder) remergeRecords(ctx context.Context, records Records) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for devID, prev := range records {
		if curr, ok := r.records[devID]; !ok {
			r.records[devID] = prev
		} else {
			curr.Queries += prev.Queries
		}
	}

	r.metrics.BufferSizeSet(ctx, float64(len(r.records)))
}
