// Package dnsdb contains types and utilities for collecting anonymous
// statistics about the Internet.
//
// TODO(a.garipov): This needs way more tests.
package dnsdb

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/miekg/dns"
)

// Interface is the DNS query database interface.
type Interface interface {
	// Record saves anonymous data from the DNS query.
	Record(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo)
}

// Empty is a DNS query database that does nothing.
type Empty struct{}

// type check
var _ Interface = Empty{}

// Record implements the Interface interface for Empty.
func (Empty) Record(_ context.Context, _ *dns.Msg, _ *agd.RequestInfo) {}

// Default is the default DNSDB implementation.
type Default struct {
	logger  *slog.Logger
	buffer  *atomic.Pointer[buffer]
	errColl errcoll.Interface
	metrics Metrics
	maxSize int
}

// DefaultConfig is the default DNS database configuration structure.
type DefaultConfig struct {
	// Logger is used to log the operation of the DNS database.  It must not be
	// nil.
	Logger *slog.Logger

	// ErrColl is used to collect HTTP errors.  It must not be nil.
	ErrColl errcoll.Interface

	// Metrics is used for the collection of the DNS database statistics.  It
	// must not be nil.
	Metrics Metrics

	// MaxSize is the maximum amount of records in the memory buffer.  It must
	// be positive.
	MaxSize int
}

// New creates a new default DNS database.  c must not be nil.
func New(c *DefaultConfig) (db *Default) {
	db = &Default{
		logger:  c.Logger,
		buffer:  &atomic.Pointer[buffer]{},
		errColl: c.ErrColl,
		metrics: c.Metrics,
		maxSize: c.MaxSize,
	}

	db.buffer.Store(&buffer{
		mu:      &sync.Mutex{},
		entries: map[recordKey]*recordValue{},
		maxSize: db.maxSize,
	})

	return db
}

// type check
var _ Interface = (*Default)(nil)

// Record implements the Interface interface for *Default.  It saves a DNS
// response to its in-memory buffer.
func (db *Default) Record(ctx context.Context, m *dns.Msg, ri *agd.RequestInfo) {
	if isIgnoredMessage(m) {
		return
	}

	q := m.Question[0]
	if isIgnoredQuestion(q) {
		return
	}

	// #nosec G115 -- RCODE is currently defined to be 16 bit or less.
	count, ok := db.buffer.Load().add(ri.Host, m.Answer, q.Qtype, dnsmsg.RCode(m.Rcode))
	if ok {
		db.metrics.SetRecordCount(ctx, count)
	}
}

// reset returns buffered records and resets the database.
func (db *Default) reset(ctx context.Context) (records []*record) {
	start := time.Now()

	prevBuf := db.buffer.Swap(&buffer{
		mu:      &sync.Mutex{},
		entries: map[recordKey]*recordValue{},
		maxSize: db.maxSize,
	})

	records = prevBuf.all()

	db.metrics.SetRecordCount(ctx, 0)
	db.metrics.ObserveRotation(ctx, time.Since(start))

	return records
}

// isIgnoredMessage returns true if m must be ignored by DNS database.
func isIgnoredMessage(m *dns.Msg) (ok bool) {
	return m == nil ||
		!m.Response ||
		len(m.Question) != 1 ||
		m.Rcode != dns.RcodeSuccess
}

// isIgnoredQuestion returns true if q must be ignored by DNS database.
func isIgnoredQuestion(q dns.Question) (ok bool) {
	return (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) ||
		// Android metric domain must be ignored by DNSDB to avoid filling it
		// with unnecessary garbage that we don't really need.
		agdnet.AndroidMetricDomainReplacement(q.Name) != ""
}
