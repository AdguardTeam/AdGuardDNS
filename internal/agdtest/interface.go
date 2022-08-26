package agdtest

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/miekg/dns"
)

// Interface Mocks
//
// Keep entities in this file in alphabetic order.

// agd.ErrorCollector

// type check
var _ agd.ErrorCollector = (*ErrorCollector)(nil)

// ErrorCollector is an agd.ErrorCollector for tests.
//
// TODO(a.garipov): Actually test the error collection where this is used.
type ErrorCollector struct {
	OnCollect func(ctx context.Context, err error)
}

// Collect implements the agd.ErrorCollector interface for *ErrorCollector.
func (c *ErrorCollector) Collect(ctx context.Context, err error) {
	c.OnCollect(ctx, err)
}

// agd.ProfileDB

// type check
var _ agd.ProfileDB = (*ProfileDB)(nil)

// ProfileDB is an agd.ProfileDB for tests.
type ProfileDB struct {
	OnProfileByDeviceID func(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error)
	OnProfileByIP func(
		ctx context.Context,
		ip netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error)
}

// ProfileByDeviceID implements the agd.ProfileDB interface for *ProfileDB.
func (db *ProfileDB) ProfileByDeviceID(
	ctx context.Context,
	id agd.DeviceID,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnProfileByDeviceID(ctx, id)
}

// ProfileByIP implements the agd.ProfileDB interface for *ProfileDB.
func (db *ProfileDB) ProfileByIP(
	ctx context.Context,
	ip netip.Addr,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnProfileByIP(ctx, ip)
}

// agd.ProfileStorage

// type check
var _ agd.ProfileStorage = (*ProfileStorage)(nil)

// ProfileStorage is a agd.ProfileStorage for tests.
type ProfileStorage struct {
	OnProfiles func(
		ctx context.Context,
		req *agd.PSProfilesRequest,
	) (resp *agd.PSProfilesResponse, err error)
}

// Profiles implements the agd.ProfileStorage interface for *ProfileStorage.
func (ds *ProfileStorage) Profiles(
	ctx context.Context,
	req *agd.PSProfilesRequest,
) (resp *agd.PSProfilesResponse, err error) {
	return ds.OnProfiles(ctx, req)
}

// agd.Refresher

// type check
var _ agd.Refresher = (*Refresher)(nil)

// Refresher is an agd.Refresher for tests.
type Refresher struct {
	OnRefresh func(ctx context.Context) (err error)
}

// Refresh implements the agd.Refresher interface for *Refresher.
func (r *Refresher) Refresh(ctx context.Context) (err error) {
	return r.OnRefresh(ctx)
}

// agd.Resolver

// type check
var _ agd.Resolver = (*Resolver)(nil)

// Resolver is an agd.Resolver for tests.
type Resolver struct {
	OnLookupIP func(ctx context.Context, network, addr string) (ips []net.IP, err error)
}

// LookupIP implements the agd.Resolver interface for *Resolver.
func (r *Resolver) LookupIP(
	ctx context.Context,
	network string,
	addr string,
) (ips []net.IP, err error) {
	return r.OnLookupIP(ctx, network, addr)
}

// Package BillStat

// billstat.Recorder

// type check
var _ billstat.Recorder = (*BillStatRecorder)(nil)

// BillStatRecorder is a billstat.Recorder for tests.
type BillStatRecorder struct {
	OnRecord func(
		ctx context.Context,
		id agd.DeviceID,
		ctry agd.Country,
		asn agd.ASN,
		start time.Time,
		proto agd.Protocol,
	)
}

// Record implements the billstat.Recorder interface for *BillStatRecorder.
func (r *BillStatRecorder) Record(
	ctx context.Context,
	id agd.DeviceID,
	ctry agd.Country,
	asn agd.ASN,
	start time.Time,
	proto agd.Protocol,
) {
	r.OnRecord(ctx, id, ctry, asn, start, proto)
}

// billstat.Uploader

// type check
var _ billstat.Uploader = (*BillStatUploader)(nil)

// BillStatUploader is a billstat.Uploader for tests.
type BillStatUploader struct {
	OnUpload func(ctx context.Context, records billstat.Records) (err error)
}

// Upload implements the billstat.Uploader interface for *BillStatUploader.
func (b *BillStatUploader) Upload(ctx context.Context, records billstat.Records) (err error) {
	return b.OnUpload(ctx, records)
}

// Package DNSCheck

// dnscheck.Interface

// type check
var _ dnscheck.Interface = (*DNSCheck)(nil)

// DNSCheck is a dnscheck.Interface for tests.
type DNSCheck struct {
	OnCheck func(ctx context.Context, req *dns.Msg, ri *agd.RequestInfo) (reqp *dns.Msg, err error)
}

// Check implements the dnscheck.Interface interface for *DNSCheck.
func (db *DNSCheck) Check(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (resp *dns.Msg, err error) {
	return db.OnCheck(ctx, req, ri)
}

// Package DNSDB

// dnsdb.Interface

// type check
var _ dnsdb.Interface = (*DNSDB)(nil)

// DNSDB is a dnsdb.Interface for tests.
type DNSDB struct {
	OnRecord func(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo)
}

// Record implements the dnsdb.Interface interface for *DNSDB.
func (db *DNSDB) Record(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo) {
	db.OnRecord(ctx, resp, ri)
}

// Package Filter

// filter.Interface

// type check
var _ filter.Interface = (*Filter)(nil)

// Filter is a filter.Interface for tests.
type Filter struct {
	OnFilterRequest func(
		ctx context.Context,
		req *dns.Msg,
		ri *agd.RequestInfo,
	) (r filter.Result, err error)
	OnFilterResponse func(
		ctx context.Context,
		resp *dns.Msg,
		ri *agd.RequestInfo,
	) (r filter.Result, err error)
	OnClose func() (err error)
}

// FilterRequest implements the filter.Interface interface for *Filter.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (r filter.Result, err error) {
	return f.OnFilterRequest(ctx, req, ri)
}

// FilterResponse implements the filter.Interface interface for *Filter.
func (f *Filter) FilterResponse(
	ctx context.Context,
	resp *dns.Msg,
	ri *agd.RequestInfo,
) (r filter.Result, err error) {
	return f.OnFilterResponse(ctx, resp, ri)
}

// Close implements the filter.Interface interface for *Filter.
func (f *Filter) Close() (err error) {
	return f.OnClose()
}

// filter.Storage

// type check
var _ filter.Storage = (*FilterStorage)(nil)

// FilterStorage is an filter.Storage for tests.
type FilterStorage struct {
	OnFilterFromContext func(ctx context.Context, ri *agd.RequestInfo) (f filter.Interface)
	OnHasListID         func(id agd.FilterListID) (ok bool)
}

// FilterFromContext implements the filter.Storage interface for *FilterStorage.
func (s *FilterStorage) FilterFromContext(
	ctx context.Context,
	ri *agd.RequestInfo,
) (f filter.Interface) {
	return s.OnFilterFromContext(ctx, ri)
}

// HasListID implements the filter.Storage interface for *FilterStorage.
func (s *FilterStorage) HasListID(id agd.FilterListID) (ok bool) {
	return s.OnHasListID(id)
}

// Package GeoIP

// geoip.Interface

// type check
var _ geoip.Interface = (*GeoIP)(nil)

// GeoIP is a geoip.Interface for tests.
type GeoIP struct {
	OnSubnetByLocation func(
		c agd.Country,
		a agd.ASN,
		fam agdnet.AddrFamily,
	) (n netip.Prefix, err error)
	OnData func(host string, ip netip.Addr) (l *agd.Location, err error)
}

// SubnetByLocation implements the geoip.Interface interface for *GeoIP.
func (g *GeoIP) SubnetByLocation(
	c agd.Country,
	a agd.ASN,
	fam agdnet.AddrFamily,
) (n netip.Prefix, err error) {
	return g.OnSubnetByLocation(c, a, fam)
}

// Data implements the geoip.Interface interface for *GeoIP.
func (g *GeoIP) Data(host string, ip netip.Addr) (l *agd.Location, err error) {
	return g.OnData(host, ip)
}

// Package Querylog

// querylog.Interface

// type check
var _ querylog.Interface = (*QueryLog)(nil)

// QueryLog is a querylog.Interface for tests.
type QueryLog struct {
	OnWrite func(ctx context.Context, e *querylog.Entry) (err error)
}

// Write implements the querylog.Interface interface for *QueryLog.
func (ql *QueryLog) Write(ctx context.Context, e *querylog.Entry) (err error) {
	return ql.OnWrite(ctx, e)
}

// Package RuleStat

// rulestat.Interface

// type check
var _ rulestat.Interface = (*RuleStat)(nil)

// RuleStat is a rulestat.Interface for tests.
type RuleStat struct {
	OnCollect func(ctx context.Context, id agd.FilterListID, text agd.FilterRuleText)
}

// Collect implements the rulestat.Interface interface for *RuleStat.
func (s *RuleStat) Collect(ctx context.Context, id agd.FilterListID, text agd.FilterRuleText) {
	s.OnCollect(ctx, id, text)
}

// Module DNSServer

// Package RateLimit

// ratelimit.RateLimit

// type check
var _ ratelimit.Interface = (*RateLimit)(nil)

// RateLimit is a ratelimit.Interface for tests.
type RateLimit struct {
	OnIsRateLimited func(
		ctx context.Context,
		req *dns.Msg,
		ip netip.Addr,
	) (drop, allowlisted bool, err error)
	OnCountResponses func(ctx context.Context, resp *dns.Msg, ip netip.Addr)
}

// IsRateLimited implements the ratelimit.Interface interface for *RateLimit.
func (l *RateLimit) IsRateLimited(
	ctx context.Context,
	req *dns.Msg,
	ip netip.Addr,
) (drop, allowlisted bool, err error) {
	return l.OnIsRateLimited(ctx, req, ip)
}

// CountResponses implements the ratelimit.Interface interface for
// *RateLimit.
func (l *RateLimit) CountResponses(ctx context.Context, req *dns.Msg, ip netip.Addr) {
	l.OnCountResponses(ctx, req, ip)
}
