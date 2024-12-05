package agdtest

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/AdGuardDNS/internal/rulestat"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// Interface Mocks
//
// Keep entities within a module/package in alphabetic order.

// Module AdGuardDNS

// Package access

// type check
var _ access.Interface = (*AccessManager)(nil)

// AccessManager is a [access.Interface] for tests.
type AccessManager struct {
	OnIsBlockedHost func(host string, qt uint16) (blocked bool)
	OnIsBlockedIP   func(ip netip.Addr) (blocked bool)
}

// IsBlockedHost implements the [access.Interface] interface for *AccessManager.
func (a *AccessManager) IsBlockedHost(host string, qt uint16) (blocked bool) {
	return a.OnIsBlockedHost(host, qt)
}

// IsBlockedIP implements the [access.Interface] interface for *AccessManager.
func (a *AccessManager) IsBlockedIP(ip netip.Addr) (blocked bool) {
	return a.OnIsBlockedIP(ip)
}

// Package agd

// type check
var _ agd.DeviceFinder = (*DeviceFinder)(nil)

// DeviceFinder is an [agd.DeviceFinder] for tests.
type DeviceFinder struct {
	OnFind func(
		ctx context.Context,
		req *dns.Msg,
		raddr netip.AddrPort,
		laddr netip.AddrPort,
	) (r agd.DeviceResult)
}

// Find implements the [agd.DeviceFinder] interface for *DeviceFinder.
func (f *DeviceFinder) Find(
	ctx context.Context,
	req *dns.Msg,
	raddr netip.AddrPort,
	laddr netip.AddrPort,
) (r agd.DeviceResult) {
	return f.OnFind(ctx, req, raddr, laddr)
}

// Package agdpasswd

// type check
var _ agdpasswd.Authenticator = (*Authenticator)(nil)

// Authenticator is an [agdpasswd.Authenticator] for tests.
type Authenticator struct {
	OnAuthenticate func(ctx context.Context, passwd []byte) (ok bool)
}

// Authenticate implements the [agdpasswd.Authenticator] interface for
// *Authenticator.
func (a *Authenticator) Authenticate(ctx context.Context, passwd []byte) (ok bool) {
	return a.OnAuthenticate(ctx, passwd)
}

// Package agdservice

// type check
var _ agdservice.Refresher = (*Refresher)(nil)

// Refresher is an [agdservice.Refresher] for tests.
type Refresher struct {
	OnRefresh func(ctx context.Context) (err error)
}

// Refresh implements the [agdservice.Refresher] interface for *Refresher.
func (r *Refresher) Refresh(ctx context.Context) (err error) {
	return r.OnRefresh(ctx)
}

// Package agdtime

// type check
var _ agdtime.Clock = (*Clock)(nil)

// Clock is a [agdtime.Clock] for tests.
type Clock struct {
	OnNow func() (now time.Time)
}

// Now implements the [agdtime.Clock] interface for *Clock.
func (c *Clock) Now() (now time.Time) {
	return c.OnNow()
}

// Package billstat

// type check
var _ billstat.Recorder = (*BillStatRecorder)(nil)

// BillStatRecorder is a [billstat.Recorder] for tests.
type BillStatRecorder struct {
	OnRecord func(
		ctx context.Context,
		id agd.DeviceID,
		ctry geoip.Country,
		asn geoip.ASN,
		start time.Time,
		proto agd.Protocol,
	)
}

// Record implements the [billstat.Recorder] interface for *BillStatRecorder.
func (r *BillStatRecorder) Record(
	ctx context.Context,
	id agd.DeviceID,
	ctry geoip.Country,
	asn geoip.ASN,
	start time.Time,
	proto agd.Protocol,
) {
	r.OnRecord(ctx, id, ctry, asn, start, proto)
}

// type check
var _ billstat.Uploader = (*BillStatUploader)(nil)

// BillStatUploader is a [billstat.Uploader] for tests.
type BillStatUploader struct {
	OnUpload func(ctx context.Context, records billstat.Records) (err error)
}

// Upload implements the [billstat.Uploader] interface for *BillStatUploader.
func (b *BillStatUploader) Upload(ctx context.Context, records billstat.Records) (err error) {
	return b.OnUpload(ctx, records)
}

// Package dnscheck

// type check
var _ dnscheck.Interface = (*DNSCheck)(nil)

// DNSCheck is a [dnscheck.Interface] for tests.
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

// Package dnsdb

// type check
var _ dnsdb.Interface = (*DNSDB)(nil)

// DNSDB is a [dnsdb.Interface] for tests.
type DNSDB struct {
	OnRecord func(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo)
}

// Record implements the [dnsdb.Interface] interface for *DNSDB.
func (db *DNSDB) Record(ctx context.Context, resp *dns.Msg, ri *agd.RequestInfo) {
	db.OnRecord(ctx, resp, ri)
}

// Package errcoll

// type check
var _ errcoll.Interface = (*ErrorCollector)(nil)

// ErrorCollector is an [errcoll.Interface] for tests.
//
// TODO(a.garipov): Actually test the error collection where this is used.
type ErrorCollector struct {
	OnCollect func(ctx context.Context, err error)
}

// Collect implements the [errcoll.Interface] interface for *ErrorCollector.
func (c *ErrorCollector) Collect(ctx context.Context, err error) {
	c.OnCollect(ctx, err)
}

// NewErrorCollector returns a new *ErrorCollector all methods of which panic.
func NewErrorCollector() (c *ErrorCollector) {
	return &ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic(fmt.Errorf("unexpected call to ErrorCollector.Collect(%v)", err))
		},
	}
}

// Package filter

// type check
var _ filter.Interface = (*Filter)(nil)

// Filter is a [filter.Interface] for tests.
type Filter struct {
	OnFilterRequest  func(ctx context.Context, req *filter.Request) (r filter.Result, err error)
	OnFilterResponse func(ctx context.Context, resp *filter.Response) (r filter.Result, err error)
}

// FilterRequest implements the [filter.Interface] interface for *Filter.
func (f *Filter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	return f.OnFilterRequest(ctx, req)
}

// FilterResponse implements the [filter.Interface] interface for *Filter.
func (f *Filter) FilterResponse(
	ctx context.Context,
	resp *filter.Response,
) (r filter.Result, err error) {
	return f.OnFilterResponse(ctx, resp)
}

// type check
var _ filter.HashMatcher = (*HashMatcher)(nil)

// HashMatcher is a [filter.HashMatcher] for tests.
type HashMatcher struct {
	OnMatchByPrefix func(
		ctx context.Context,
		host string,
	) (hashes []string, matched bool, err error)
}

// MatchByPrefix implements the [filter.HashMatcher] interface for *HashMatcher.
func (m *HashMatcher) MatchByPrefix(
	ctx context.Context,
	host string,
) (hashes []string, matched bool, err error) {
	return m.OnMatchByPrefix(ctx, host)
}

// type check
var _ filter.Storage = (*FilterStorage)(nil)

// FilterStorage is a [filter.Storage] for tests.
type FilterStorage struct {
	OnForConfig func(ctx context.Context, c filter.Config) (f filter.Interface)
	OnHasListID func(id filter.ID) (ok bool)
}

// ForConfig implements the [filter.Storage] interface for
// *FilterStorage.
func (s *FilterStorage) ForConfig(ctx context.Context, c filter.Config) (f filter.Interface) {
	return s.OnForConfig(ctx, c)
}

// HasListID implements the [filter.Storage] interface for *FilterStorage.
func (s *FilterStorage) HasListID(id filter.ID) (ok bool) {
	return s.OnHasListID(id)
}

// Package geoip

// type check
var _ geoip.Interface = (*GeoIP)(nil)

// GeoIP is a [geoip.Interface] for tests.
type GeoIP struct {
	OnData             func(host string, ip netip.Addr) (l *geoip.Location, err error)
	OnSubnetByLocation func(l *geoip.Location, fam netutil.AddrFamily) (n netip.Prefix, err error)
}

// Data implements the [geoip.Interface] interface for *GeoIP.
func (g *GeoIP) Data(host string, ip netip.Addr) (l *geoip.Location, err error) {
	return g.OnData(host, ip)
}

// SubnetByLocation implements the [geoip.Interface] interface for *GeoIP.
func (g *GeoIP) SubnetByLocation(
	l *geoip.Location,
	fam netutil.AddrFamily,
) (n netip.Prefix, err error) {
	return g.OnSubnetByLocation(l, fam)
}

// NewGeoIP returns a new *GeoIP all methods of which panic.
func NewGeoIP() (c *GeoIP) {
	return &GeoIP{
		OnData: func(host string, ip netip.Addr) (l *geoip.Location, err error) {
			panic(fmt.Errorf("unexpected call to GeoIP.Data(%v, %v)", host, ip))
		},
		OnSubnetByLocation: func(
			l *geoip.Location,
			fam netutil.AddrFamily,
		) (n netip.Prefix, err error) {
			panic(fmt.Errorf("unexpected call to GeoIP.SubnetByLocation(%v, %v)", l, fam))
		},
	}
}

// Package profiledb

// type check
var _ profiledb.Interface = (*ProfileDB)(nil)

// ProfileDB is a [profiledb.Interface] for tests.
type ProfileDB struct {
	OnCreateAutoDevice func(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanID,
		devType agd.DeviceType,
	) (p *agd.Profile, d *agd.Device, err error)

	OnProfileByDedicatedIP func(
		ctx context.Context,
		ip netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error)

	OnProfileByDeviceID func(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error)

	OnProfileByHumanID func(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error)

	OnProfileByLinkedIP func(
		ctx context.Context,
		ip netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error)
}

// CreateAutoDevice implements the [profiledb.Interface] interface for
// *ProfileDB.
func (db *ProfileDB) CreateAutoDevice(
	ctx context.Context,
	id agd.ProfileID,
	humanID agd.HumanID,
	devType agd.DeviceType,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnCreateAutoDevice(ctx, id, humanID, devType)
}

// ProfileByDedicatedIP implements the [profiledb.Interface] interface for
// *ProfileDB.
func (db *ProfileDB) ProfileByDedicatedIP(
	ctx context.Context,
	ip netip.Addr,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnProfileByDedicatedIP(ctx, ip)
}

// ProfileByDeviceID implements the [profiledb.Interface] interface for
// *ProfileDB.
func (db *ProfileDB) ProfileByDeviceID(
	ctx context.Context,
	id agd.DeviceID,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnProfileByDeviceID(ctx, id)
}

// ProfileByHumanID implements the [profiledb.Interface] interface for
// *ProfileDB.
func (db *ProfileDB) ProfileByHumanID(
	ctx context.Context,
	id agd.ProfileID,
	humanID agd.HumanIDLower,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnProfileByHumanID(ctx, id, humanID)
}

// ProfileByLinkedIP implements the [profiledb.Interface] interface for
// *ProfileDB.
func (db *ProfileDB) ProfileByLinkedIP(
	ctx context.Context,
	ip netip.Addr,
) (p *agd.Profile, d *agd.Device, err error) {
	return db.OnProfileByLinkedIP(ctx, ip)
}

// NewProfileDB returns a new *ProfileDB all methods of which panic.
func NewProfileDB() (db *ProfileDB) {
	return &ProfileDB{
		OnCreateAutoDevice: func(
			_ context.Context,
			id agd.ProfileID,
			humanID agd.HumanID,
			devType agd.DeviceType,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic(fmt.Errorf(
				"unexpected call to ProfileDB.CreateAutoDevice(%v, %v, %v)",
				id,
				humanID,
				devType,
			))
		},

		OnProfileByDedicatedIP: func(
			_ context.Context,
			ip netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic(fmt.Errorf("unexpected call to ProfileDB.ProfileByDedicatedIP(%v)", ip))
		},

		OnProfileByDeviceID: func(
			_ context.Context,
			id agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic(fmt.Errorf("unexpected call to ProfileDB.ProfileByDeviceID(%v)", id))
		},

		OnProfileByHumanID: func(
			_ context.Context,
			profID agd.ProfileID,
			humanID agd.HumanIDLower,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic(fmt.Errorf(
				"unexpected call to ProfileDB.ProfileByHumanID(%v, %v)",
				profID,
				humanID,
			))
		},

		OnProfileByLinkedIP: func(
			_ context.Context,
			ip netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic(fmt.Errorf("unexpected call to ProfileDB.ProfileByLinkedIP(%v)", ip))
		},
	}
}

// type check
var _ profiledb.Storage = (*ProfileStorage)(nil)

// ProfileStorage is a [profiledb.Storage] implementation for tests.
type ProfileStorage struct {
	OnCreateAutoDevice func(
		ctx context.Context,
		req *profiledb.StorageCreateAutoDeviceRequest,
	) (resp *profiledb.StorageCreateAutoDeviceResponse, err error)

	OnProfiles func(
		ctx context.Context,
		req *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error)
}

// CreateAutoDevice implements the [profiledb.Storage] interface for
// *ProfileStorage.
func (s *ProfileStorage) CreateAutoDevice(
	ctx context.Context,
	req *profiledb.StorageCreateAutoDeviceRequest,
) (resp *profiledb.StorageCreateAutoDeviceResponse, err error) {
	return s.OnCreateAutoDevice(ctx, req)
}

// Profiles implements the [profiledb.Storage] interface for *ProfileStorage.
func (s *ProfileStorage) Profiles(
	ctx context.Context,
	req *profiledb.StorageProfilesRequest,
) (resp *profiledb.StorageProfilesResponse, err error) {
	return s.OnProfiles(ctx, req)
}

// Package querylog

// type check
var _ querylog.Interface = (*QueryLog)(nil)

// QueryLog is a [querylog.Interface] for tests.
type QueryLog struct {
	OnWrite func(ctx context.Context, e *querylog.Entry) (err error)
}

// Write implements the [querylog.Interface] interface for *QueryLog.
func (ql *QueryLog) Write(ctx context.Context, e *querylog.Entry) (err error) {
	return ql.OnWrite(ctx, e)
}

// Package rulestat

// type check
var _ rulestat.Interface = (*RuleStat)(nil)

// RuleStat is a [rulestat.Interface] for tests.
type RuleStat struct {
	OnCollect func(ctx context.Context, id filter.ID, text filter.RuleText)
}

// Collect implements the [rulestat.Interface] interface for *RuleStat.
func (s *RuleStat) Collect(ctx context.Context, id filter.ID, text filter.RuleText) {
	s.OnCollect(ctx, id, text)
}

// Module dnsserver

// Package netext

var _ netext.ListenConfig = (*ListenConfig)(nil)

// ListenConfig is a [netext.ListenConfig] for tests.
type ListenConfig struct {
	OnListen       func(ctx context.Context, network, address string) (l net.Listener, err error)
	OnListenPacket func(
		ctx context.Context,
		network string,
		address string,
	) (conn net.PacketConn, err error)
}

// Listen implements the [netext.ListenConfig] interface for *ListenConfig.
func (c *ListenConfig) Listen(
	ctx context.Context,
	network string,
	address string,
) (l net.Listener, err error) {
	return c.OnListen(ctx, network, address)
}

// ListenPacket implements the [netext.ListenConfig] interface for
// *ListenConfig.
func (c *ListenConfig) ListenPacket(
	ctx context.Context,
	network string,
	address string,
) (conn net.PacketConn, err error) {
	return c.OnListenPacket(ctx, network, address)
}

// Package ratelimit

// type check
var _ ratelimit.Interface = (*RateLimit)(nil)

// RateLimit is a [ratelimit.Interface] for tests.
type RateLimit struct {
	OnIsRateLimited func(
		ctx context.Context,
		req *dns.Msg,
		ip netip.Addr,
	) (shouldDrop, isAllowlisted bool, err error)
	OnCountResponses func(ctx context.Context, resp *dns.Msg, ip netip.Addr)
}

// IsRateLimited implements the [ratelimit.Interface] interface for *RateLimit.
func (l *RateLimit) IsRateLimited(
	ctx context.Context,
	req *dns.Msg,
	ip netip.Addr,
) (shouldDrop, isAllowlisted bool, err error) {
	return l.OnIsRateLimited(ctx, req, ip)
}

// CountResponses implements the [ratelimit.Interface] interface for *RateLimit.
func (l *RateLimit) CountResponses(ctx context.Context, req *dns.Msg, ip netip.Addr) {
	l.OnCountResponses(ctx, req, ip)
}

// NewRateLimit returns a new *RateLimit all methods of which panic.
func NewRateLimit() (c *RateLimit) {
	return &RateLimit{
		OnIsRateLimited: func(
			_ context.Context,
			req *dns.Msg,
			addr netip.Addr,
		) (shouldDrop, isAllowlisted bool, err error) {
			panic(fmt.Errorf("unexpected call to RateLimit.IsRateLimited(%v, %v)", req, addr))
		},
		OnCountResponses: func(_ context.Context, resp *dns.Msg, addr netip.Addr) {
			panic(fmt.Errorf("unexpected call to RateLimit.CountResponses(%v, %v)", resp, addr))
		},
	}
}

// RemoteKV is an [remotekv.Interface] implementation for tests.
type RemoteKV struct {
	OnGet func(ctx context.Context, key string) (val []byte, ok bool, err error)
	OnSet func(ctx context.Context, key string, val []byte) (err error)
}

// type check
var _ remotekv.Interface = (*RemoteKV)(nil)

// Get implements the [remotekv.Interface] interface for *RemoteKV.
func (kv *RemoteKV) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	return kv.OnGet(ctx, key)
}

// Set implements the [remotekv.Interface] interface for *RemoteKV.
func (kv *RemoteKV) Set(ctx context.Context, key string, val []byte) (err error) {
	return kv.OnSet(ctx, key, val)
}

// Module prometheus

// PrometheusRegisterer is a [prometheus.Registerer] implementation for tests.
type PrometheusRegisterer struct {
	OnRegister     func(prometheus.Collector) (err error)
	OnMustRegister func(...prometheus.Collector)
	OnUnregister   func(prometheus.Collector) (ok bool)
}

// type check
var _ prometheus.Registerer = (*PrometheusRegisterer)(nil)

// Register implements the [prometheus.Registerer] interface for
// *PrometheusRegisterer.
func (r *PrometheusRegisterer) Register(c prometheus.Collector) (err error) {
	return r.OnRegister(c)
}

// MustRegister implements the [prometheus.Registerer] interface for
// *PrometheusRegisterer.
func (r *PrometheusRegisterer) MustRegister(collectors ...prometheus.Collector) {
	r.OnMustRegister(collectors...)
}

// Unregister implements the [prometheus.Registerer] interface for
// *PrometheusRegisterer.
func (r *PrometheusRegisterer) Unregister(c prometheus.Collector) (ok bool) {
	return r.OnUnregister(c)
}

// NewTestPrometheusRegisterer returns a [prometheus.Registerer] implementation
// that does nothing and returns nil from [prometheus.Registerer.Register] and
// true from [prometheus.Registerer.Unregister].
func NewTestPrometheusRegisterer() (r *PrometheusRegisterer) {
	return &PrometheusRegisterer{
		OnRegister:     func(_ prometheus.Collector) (err error) { return nil },
		OnMustRegister: func(_ ...prometheus.Collector) {},
		OnUnregister:   func(_ prometheus.Collector) (ok bool) { return true },
	}
}
