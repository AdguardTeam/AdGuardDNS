package dnsdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"go.etcd.io/bbolt"
)

// BoldDB-Based DNSDB

// recordBuffer is an in-memory buffer of DNSDB records.
type recordBuffer map[string][]*record

// Bolt is BoltDB-based DNSDB implementation.
type Bolt struct {
	// dumpMu is used to make sure that the CSV endpoint is only used by one
	// client at a time, as well as that the periodic flushing doesn't interfere
	// with it.
	//
	// TODO(a.garipov): Consider adding rate limiting.
	dumpMu *sync.Mutex

	bufferMu *sync.Mutex
	buffer   recordBuffer

	errColl agd.ErrorCollector

	path string
}

// BoltConfig is the BoltDB-based DNSDB configuration structure.
type BoltConfig struct {
	// ErrColl is used to collect HTTP errors as well as
	ErrColl agd.ErrorCollector

	// Path is the path to the BoltDB file.
	Path string
}

// NewBolt creates a new BoltDB-based DNSDB.  c must not be nil.
func NewBolt(c *BoltConfig) (db *Bolt) {
	db = &Bolt{
		dumpMu: &sync.Mutex{},

		bufferMu: &sync.Mutex{},
		buffer:   recordBuffer{},

		errColl: c.ErrColl,

		path: c.Path,
	}

	return db
}

// type check
var _ Interface = (*Bolt)(nil)

// Record implements the Interface interface for *Bolt.  It saves a DNS response
// to its in-memory buffer.
func (db *Bolt) Record(ctx context.Context, m *dns.Msg, ri *agd.RequestInfo) {
	if isIgnoredMessage(m) {
		return
	}

	q := m.Question[0]
	if isIgnoredQuestion(q) {
		return
	}

	key := requestKey(ri.Host, q.Qtype)
	recs := toDBRecords(q.Qtype, ri.Host, m.Answer, dnsmsg.RCode(m.Rcode))
	db.saveToBuffer(key, recs)
}

// saveToBuffer saves recs to the in-memory buffer.
func (db *Bolt) saveToBuffer(key string, recs []*record) {
	db.bufferMu.Lock()
	defer db.bufferMu.Unlock()

	prevRecs, ok := db.buffer[key]
	if !ok {
		db.buffer[key] = recs
		metrics.DNSDBBufferSize.Inc()

		return
	}

	// Consider that new answers either don't appear between rotations of the
	// database or don't matter, and so don't merge new records with the old
	// ones.  Just bump the hit counters.
	for _, r := range prevRecs {
		r.Hits++
	}
}

// type check
var _ agd.Refresher = (*Bolt)(nil)

// Refresh implements the agd.Refresher interface for *Bolt.  It flushes the
// current in-memory buffer data to disk.
func (db *Bolt) Refresh(ctx context.Context) (err error) {
	db.dumpMu.Lock()
	defer db.dumpMu.Unlock()

	_, err = db.flush(ctx, false)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}

// flush saves the buffered records to the local BoltDB database.  If rotate is
// true, it also rotates the database file and returns the path to the previous
// database file.
func (db *Bolt) flush(ctx context.Context, rotate bool) (prev string, err error) {
	start := time.Now()
	// TODO(a.garipov): Consider only replacing the buffer with an empty one if
	// the write was successful.
	buffer := db.replaceBuffer()
	bdb, err := openBolt(db.path)
	if err != nil {
		return "", fmt.Errorf("opening boltdb: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, bdb.Close()) }()

	err = bdb.Batch(boltFlushFunc(ctx, buffer, db.errColl))
	if err != nil {
		return "", fmt.Errorf("saving: %w", err)
	}

	if rotate {
		prev, err = db.rotate()
		if err != nil {
			return prev, fmt.Errorf("rotating: %w", err)
		}
	}

	metrics.DNSDBSaveDuration.Observe(time.Since(start).Seconds())

	return prev, nil
}

// replaceBuffer replaced db's current buffer with a new one and returns the
// previous one.
func (db *Bolt) replaceBuffer() (prev recordBuffer) {
	db.bufferMu.Lock()
	defer db.bufferMu.Unlock()

	prev, db.buffer = db.buffer, recordBuffer{}
	metrics.DNSDBBufferSize.Set(0)

	return prev
}

// recordsBucket is the name of the bucket with the DNSDB records.
const recordsBucket = "records"

// openBolt opens and initializes the BoltDB file.
func openBolt(dbPath string) (bdb *bbolt.DB, err error) {
	bdb, err = bbolt.Open(dbPath, agd.DefaultPerm, nil)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}

	err = bdb.Update(func(tx *bbolt.Tx) (ferr error) {
		_, ferr = tx.CreateBucketIfNotExists([]byte(recordsBucket))

		return ferr
	})
	if err != nil {
		return nil, fmt.Errorf("initializing: %w", err)
	}

	return bdb, nil
}

// boltTxFunc is an alias for the type consumed by bbolt.(*DB).Batch.
type boltTxFunc = func(tx *bbolt.Tx) (err error)

// boltFlushFunc returns a function that reads data from the existing DNSDB
// file, updates the current buffer, and writes it back.
//
// f always returns nil; all errors are reported using errColl.
func boltFlushFunc(
	ctx context.Context,
	buffer recordBuffer,
	errColl agd.ErrorCollector,
) (f boltTxFunc) {
	return func(tx *bbolt.Tx) (err error) {
		b := tx.Bucket([]byte(recordsBucket))

		for rk, recs := range buffer {
			k := []byte(rk)
			err = addExisting(b, k, recs)
			if err != nil {
				agd.Collectf(ctx, errColl, "dnsdb: adding existing data for %s: %w", rk, err)

				// Consider errors from reading the previous database
				// non-critical.
			}

			var dbData []byte
			dbData, err = encode(recs)
			if err != nil {
				agd.Collectf(ctx, errColl, "dnsdb: encoding data for %s: %w", rk, err)

				continue
			}

			err = b.Put(k, dbData)
			if err != nil {
				agd.Collectf(ctx, errColl, "dnsdb: writing data for %s: %w", rk, err)

				// Consider errors from writing a single key non-critical.
			}
		}

		metrics.DNSDBSize.Set(float64(b.Stats().KeyN))

		return nil
	}
}

// addExisting looks up previous data for key in b and updates recs with those
// data if there are any.
func addExisting(b *bbolt.Bucket, key []byte, recs []*record) (err error) {
	prevData := b.Get(key)
	if len(prevData) == 0 {
		return nil
	}

	var prevRecs []*record
	prevRecs, err = decode(prevData)
	if err != nil {
		return fmt.Errorf("decoding previous value: %w", err)
	}

	if len(prevRecs) == 0 {
		return nil
	}

	// Use only the first Hits value, because all records share it.
	prevHits := prevRecs[0].Hits
	for _, r := range recs {
		r.Hits += prevHits
	}

	return nil
}

// requestKey returns a key for identifying a request.
func requestKey(name string, qt dnsmsg.RRType) (key string) {
	return name + "_" + dns.TypeToString[qt]
}

// rotate moves the current DB file to a temporary file and returns the path to
// that temporary file.
func (db *Bolt) rotate() (prev string, err error) {
	prevBase := fmt.Sprintf("%s.%d", filepath.Base(db.path), time.Now().Unix())
	prev = filepath.Join(os.TempDir(), prevBase)
	err = os.Rename(db.path, prev)
	if err != nil {
		return "", fmt.Errorf("renaming prev db: %w", err)
	}

	log.Info("dnsdb: renamed %q to %q", db.path, prev)

	metrics.DNSDBSize.Set(0)
	metrics.DNSDBRotateTime.SetToCurrentTime()

	return prev, nil
}
