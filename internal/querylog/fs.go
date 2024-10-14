package querylog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"golang.org/x/exp/rand"
)

// FileSystemConfig is the configuration of the file system query log.  All
// fields must not be empty.
type FileSystemConfig struct {
	// Logger is used for debug logging.
	Logger *slog.Logger

	// Path is the path to the log file.
	Path string

	// RandSeed is used to set the "rn" property in JSON objects.
	RandSeed uint64
}

// NewFileSystem creates a new file system query log.  The log is safe for
// concurrent use.  c must not be nil.
func NewFileSystem(c *FileSystemConfig) (l *FileSystem) {
	rng := rand.New(&rand.LockedSource{})
	rng.Seed(c.RandSeed)

	return &FileSystem{
		logger: c.Logger,
		bufferPool: syncutil.NewPool(func() (v *entryBuffer) {
			return &entryBuffer{
				ent: &jsonlEntry{},
				buf: &bytes.Buffer{},
			}
		}),
		rng:  rng,
		path: c.Path,
	}
}

// entryBuffer is a struct with two fields for caching entry that is being
// written.  Using this struct allows us to remove allocations on every write.
type entryBuffer struct {
	ent *jsonlEntry
	buf *bytes.Buffer
}

// FileSystem is the file system implementation of the AdGuard DNS query log.
type FileSystem struct {
	// logger is used for debug logging.
	logger *slog.Logger

	// bufferPool is a pool with [*entryBuffer] instances used to avoid extra
	// allocations when serializing query log items to JSON and writing them.
	bufferPool *syncutil.Pool[entryBuffer]

	// rng is used to generate random numbers for the "rn" property in the
	// resulting JSON.
	rng *rand.Rand

	// path is the path to the query log file.
	path string
}

// type check
var _ Interface = (*FileSystem)(nil)

// Write implements the Interface interface for *FileSystem.
func (l *FileSystem) Write(ctx context.Context, e *Entry) (err error) {
	optslog.Trace1(ctx, l.logger, "writing file logs", "req_id", e.RequestID)
	defer func() {
		optslog.Trace2(
			ctx,
			l.logger,
			"writing file logs",
			"req_id", e.RequestID,
			slogutil.KeyError, err,
		)
	}()

	startTime := time.Now()
	defer func() {
		metrics.QueryLogWriteDuration.Observe(time.Since(startTime).Seconds())
		metrics.QueryLogItemsCount.Inc()
	}()

	entBuf := l.bufferPool.Get()
	defer l.bufferPool.Put(entBuf)
	entBuf.buf.Reset()

	var remoteIP *netip.Addr
	if e.RemoteIP != (netip.Addr{}) {
		remoteIP = &e.RemoteIP
	}

	c, id, r := resultData(e.RequestResult, e.ResponseResult)
	*entBuf.ent = jsonlEntry{
		RequestID:       e.RequestID.String(),
		ProfileID:       e.ProfileID,
		DeviceID:        e.DeviceID,
		ClientCountry:   e.ClientCountry,
		ResponseCountry: e.ResponseCountry,
		DomainFQDN:      e.DomainFQDN,
		FilterListID:    id,
		FilterRule:      r,
		Timestamp:       e.Time.UnixMilli(),
		ClientASN:       e.ClientASN,
		Elapsed:         l.convertElapsed(ctx, e.Elapsed),
		RequestType:     e.RequestType,
		ResponseCode:    e.ResponseCode,
		// #nosec G115 -- The overflow is safe, since this is a random number.
		Random:     uint16(l.rng.Uint32()),
		DNSSEC:     mathutil.BoolToNumber[uint8](e.DNSSEC),
		Protocol:   e.Protocol,
		ResultCode: c,
		RemoteIP:   remoteIP,
	}

	var f *os.File
	f, err = os.OpenFile(l.path, agd.DefaultWOFlags, agd.DefaultPerm)
	if err != nil {
		return fmt.Errorf("opening query log file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	// Serialize the query log entry to that buffer as a JSON.
	// Do not write an additional line feed, because Encode already does that.
	err = json.NewEncoder(entBuf.buf).Encode(entBuf.ent)
	if err != nil {
		return fmt.Errorf("writing log: %w", err)
	}

	var written int64
	written, err = entBuf.buf.WriteTo(f)
	if err != nil {
		return fmt.Errorf("writing log: %w", err)
	}

	metrics.QueryLogItemSize.Observe(float64(written))

	return nil
}

// convertElapsed converts the elapsed duration and writes warnings to the log
// if the value is outside of the allowed limits.
func (l *FileSystem) convertElapsed(ctx context.Context, elapsed time.Duration) (elapsedMs uint32) {
	elapsedMs64 := elapsed.Milliseconds()
	if elapsedMs64 < 0 {
		l.logger.WarnContext(ctx, "elapsed below zero; setting to zero")

		return 0
	}

	const maxElapsedMs = math.MaxUint32
	if elapsedMs64 > maxElapsedMs {
		l.logger.WarnContext(ctx, "elapsed above max uint32; setting to max uint32")

		return maxElapsedMs
	}

	return uint32(elapsedMs64)
}
