package querylog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/syncutil"
)

// FileSystemConfig is the configuration of the file system query log.
type FileSystemConfig struct {
	// Path is the path to the log file.
	Path string
}

// NewFileSystem creates a new file system query log.  The log is safe for
// concurrent use.
func NewFileSystem(c *FileSystemConfig) (l *FileSystem) {
	return &FileSystem{
		path: c.Path,
		bufferPool: syncutil.NewPool(func() (v *entryBuffer) {
			return &entryBuffer{
				ent: &jsonlEntry{},
				buf: &bytes.Buffer{},
			}
		}),
	}
}

// entryBuffer is a struct with two fields for caching entry that is being
// written. Using this struct allows us to remove allocations on every write.
type entryBuffer struct {
	ent *jsonlEntry
	buf *bytes.Buffer
}

// FileSystem is the file system implementation of the AdGuard DNS query log.
type FileSystem struct {
	// bufferPool is a pool with [*entryBuffer] instances used to avoid extra
	// allocations when serializing query log items to JSON and writing them.
	bufferPool *syncutil.Pool[entryBuffer]

	// path is the path to the query log file.
	path string
}

// type check
var _ Interface = (*FileSystem)(nil)

// Write implements the Interface interface for *FileSystem.
func (l *FileSystem) Write(_ context.Context, e *Entry) (err error) {
	optlog.Debug1("writing file logs for request %q", e.RequestID)
	defer func() {
		optlog.Debug2("finished writing file logs for request %q, errors: %v", e.RequestID, err)
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
		Elapsed:         e.Elapsed,
		RequestType:     e.RequestType,
		DNSSEC:          mathutil.BoolToNumber[uint8](e.DNSSEC),
		Protocol:        e.Protocol,
		ResultCode:      c,
		ResponseCode:    e.ResponseCode,
		RemoteIP:        remoteIP,
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
