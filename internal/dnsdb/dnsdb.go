// Package dnsdb contains types and utilities for collecting anonymous
// statistics about the Internet.
package dnsdb

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/miekg/dns"
)

// Common Types, Functions, And Constants

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

// isIgnoredMessage returns true if m must be ignored by DNSDB.
func isIgnoredMessage(m *dns.Msg) (ok bool) {
	return m == nil ||
		!m.Response ||
		len(m.Question) != 1 ||
		m.Rcode != dns.RcodeSuccess
}

// isIgnoredQuestion returns true if q must be ignored by DNSDB.
func isIgnoredQuestion(q dns.Question) (ok bool) {
	return (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) ||
		// Android metric domain must be ignored by DNSDB to avoid filling it
		// with unnecessary garbage that we don't really need.
		agdnet.AndroidMetricDomainReplacement(q.Name) != ""
}
