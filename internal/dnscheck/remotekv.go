package dnscheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	cache "github.com/patrickmn/go-cache"
)

// RemoteKV is the RemoteKV KV based DNS checker.
type RemoteKV struct {
	logger  *slog.Logger
	metrics Metrics

	// mu protects cache.  Don't use an RWMutex here, since it is expected that
	// there are about as many reads as there are writes.
	mu    *sync.Mutex
	cache *cache.Cache

	kv       remotekv.Interface
	messages *dnsmsg.Constructor

	errColl errcoll.Interface

	domains      []string
	nodeLocation string
	nodeName     string

	ipv4 []netip.Addr
	ipv6 []netip.Addr
}

// RemoteKVConfig is the configuration structure for remote KV based DNS
// checker.  All fields must be non-empty.
type RemoteKVConfig struct {
	// Logger is used to log the operation of the DNS checker.
	Logger *slog.Logger

	// Messages is the message constructor used to create DNS responses with
	// IPv4 and IPv6 IPs.
	Messages *dnsmsg.Constructor

	// Metrics is used for the collection of the DNSCheck service statistics.
	Metrics Metrics

	// RemoteKV for DNS server checking.
	RemoteKV remotekv.Interface

	// ErrColl is the error collector that is used to collect non-critical
	// errors.
	ErrColl errcoll.Interface

	// Domains are the lower-cased domain names used to detect DNS check requests.
	Domains []string

	// NodeLocation is the location of this server node.
	NodeLocation string

	// NodeName is the name of this server node.
	NodeName string

	// IPv4 are the IPv4 addresses to respond with to A requests.
	IPv4 []netip.Addr

	// IPv6 are the IPv6 addresses to respond with to AAAA requests.
	IPv6 []netip.Addr
}

// Default cache parameters.
//
// TODO(ameshkov): Consider making configurable.
const (
	defaultCacheExp = 1 * time.Minute
	defaultCacheGC  = 1 * time.Minute
)

// NewRemoteKV creates a new remote KV based DNS checker.  c must be non-nil.
func NewRemoteKV(c *RemoteKVConfig) (dc *RemoteKV) {
	return &RemoteKV{
		logger:       c.Logger,
		metrics:      c.Metrics,
		mu:           &sync.Mutex{},
		cache:        cache.New(defaultCacheExp, defaultCacheGC),
		kv:           c.RemoteKV,
		messages:     c.Messages,
		errColl:      c.ErrColl,
		domains:      c.Domains,
		nodeLocation: c.NodeLocation,
		nodeName:     c.NodeName,
		ipv4:         slices.Clone(c.IPv4),
		ipv6:         slices.Clone(c.IPv6),
	}
}

// type check
var _ Interface = (*RemoteKV)(nil)

// Check implements the Interface interface for *RemoteKV.  ctx must contain
// request info (retrieved by [dnsserver.MustRequestInfoFromContext]).
func (dc *RemoteKV) Check(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (resp *dns.Msg, err error) {
	var matched bool
	defer func() {
		dc.metrics.HandleError(ctx, reqMtrcTypeDNS, errMetricsType(err))

		if !matched {
			return
		}

		dc.metrics.HandleRequest(ctx, reqMtrcTypeDNS, err == nil)
	}()

	var randomID string
	randomID, matched, err = randomIDFromDomain(ri.Host, dc.domains)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	} else if !matched {
		// Not a dnscheck domain, just ignore the request.
		return nil, nil
	} else if randomID == "" {
		return dc.resp(ri, req)
	}

	inf := dc.newInfo(ctx, ri)
	b, err := json.Marshal(inf)
	if err != nil {
		return nil, fmt.Errorf("encoding value for key %q for remote kv: %w", randomID, err)
	}

	dc.addToCache(randomID, b)

	err = dc.kv.Set(ctx, randomID, b)
	if err != nil {
		errcoll.Collect(ctx, dc.errColl, dc.logger, "remote kv setting", err)
	}

	return dc.resp(ri, req)
}

// addToCache adds inf into cache using randomID as key.  It's safe for
// concurrent use.
func (dc *RemoteKV) addToCache(randomID string, inf []byte) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.cache.SetDefault(randomID, inf)
}

// serverType is a type for the enum of server types in the DNS checker HTTP
// API.
type serverType string

// Valid serverType values.
const (
	serverTypePrivate serverType = "private"
	serverTypePublic  serverType = "public"
)

// newInfo returns an information record with all available data about the
// server and the request.  ri must not be nil.  ctx must contain request info
// (retrieved by [dnsserver.MustRequestInfoFromContext]).
func (dc *RemoteKV) newInfo(ctx context.Context, ri *agd.RequestInfo) (inf *info) {
	srvInfo := ri.ServerInfo

	srvType := serverTypePublic
	if srvInfo.ProfilesEnabled {
		srvType = serverTypePrivate
	}

	inf = &info{
		ClientIP: ri.RemoteIP,

		ServerGroupName: srvInfo.GroupName,
		ServerName:      srvInfo.Name,
		ServerType:      srvType,

		NodeLocation: dc.nodeLocation,
		NodeName:     dc.nodeName,
		Protocol:     srvInfo.Protocol.String(),
		TLSCurveID:   tlsCurveID(ctx),
	}

	if p, d := ri.DeviceData(); p != nil {
		inf.ProfileID = p.ID
		inf.DeviceID = d.ID
	}

	return inf
}

// tlsCurveID returns the TLS curve ID string representation from the request
// context.  ctx must contain request info (retrieved by
// [dnsserver.MustRequestInfoFromContext]).
func tlsCurveID(ctx context.Context) (curveIDStr string) {
	srvReqInfo := dnsserver.MustRequestInfoFromContext(ctx)
	if srvReqInfo.TLS == nil {
		return ""
	}

	curveID := srvReqInfo.TLS.CurveID
	if curveID != tls.CurveID(0) {
		return curveID.String()
	}

	return ""
}

// resp returns the corresponding response.
//
// TODO(e.burkov):  Inspect the reason for using different message constructors
// for different DNS types, and consider using only one of them.
func (dc *RemoteKV) resp(ri *agd.RequestInfo, req *dns.Msg) (resp *dns.Msg, err error) {
	qt := ri.QType

	if qt != dns.TypeA && qt != dns.TypeAAAA {
		return ri.Messages.NewRespRCode(req, dns.RcodeSuccess), nil
	}

	if qt == dns.TypeA {
		return dc.messages.NewRespIP(req, dc.ipv4...)
	}

	return dc.messages.NewRespIP(req, dc.ipv6...)
}

// type check
var _ http.Handler = (*RemoteKV)(nil)

// ServeHTTP implements the http.Handler interface for *RemoteKV.
//
// TODO(a.garipov):  Find ways of merging the attributes of [RemoteKV.logger]
// and the logger that websvc adds.
func (dc *RemoteKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO(a.garipov): Put this into constant here and in package websvc.
	if r.URL.Path == "/dnscheck/test" {
		dc.serveCheckTest(r.Context(), w, r)

		return
	}

	http.NotFound(w, r)
}

// serveCheckTest serves the client DNS check API.
//
// TODO(a.garipov): Refactor this and other HTTP handlers to return wrapped
// errors and centralize the error handling.
func (dc *RemoteKV) serveCheckTest(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	l := dc.logger.With("raddr", r.RemoteAddr)

	host, err := netutil.SplitHost(r.Host)
	if err != nil {
		l.DebugContext(ctx, "bad host", "hostport", r.Host, slogutil.KeyError, err)

		http.NotFound(w, r)

		return
	}

	randomID, matched, err := randomIDFromDomain(host, dc.domains)
	if err != nil {
		l.DebugContext(ctx, "bad request", "host", host, slogutil.KeyError, err)

		http.NotFound(w, r)

		return
	} else if !matched || randomID == "" {
		// We expect dnscheck requests to have a unique ID in the domain name.
		l.DebugContext(ctx, "bad domain", "host", host, slogutil.KeyError, err)

		http.NotFound(w, r)

		return
	}

	inf, ok, err := dc.info(ctx, randomID)
	// TODO(s.chzhen):  Use error interface instead of error value.
	if errors.Is(err, consulkv.ErrRateLimited) {
		http.Error(w, err.Error(), http.StatusTooManyRequests)

		return
	} else if err != nil {
		l.DebugContext(ctx, "getting info", "random_id", randomID, slogutil.KeyError, err)

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	} else if !ok {
		l.DebugContext(ctx, "no info", "random_id", randomID, slogutil.KeyError, err)

		http.NotFound(w, r)

		return
	}

	h := w.Header()
	h.Set(httphdr.ContentType, agdhttp.HdrValApplicationJSON)
	h.Set(httphdr.AccessControlAllowOrigin, agdhttp.HdrValWildcard)

	_, err = w.Write(inf)
	if err != nil {
		errcoll.Collect(ctx, dc.errColl, dc.logger, "http resp write", err)
	}
}

// info returns an information record by the random request ID.
func (dc *RemoteKV) info(ctx context.Context, randomID string) (inf []byte, ok bool, err error) {
	defer func() {
		dc.metrics.HandleError(ctx, reqMtrcTypeHTTP, errMetricsType(err))
		dc.metrics.HandleRequest(ctx, reqMtrcTypeHTTP, err == nil)
	}()

	defer func() { err = errors.Annotate(err, "getting from remote kv: %w") }()

	dc.mu.Lock()
	defer dc.mu.Unlock()

	infoVal, ok := dc.cache.Get(randomID)
	if ok {
		return infoVal.([]byte), true, nil
	}

	inf, ok, err = dc.kv.Get(ctx, randomID)
	if err != nil {
		errcoll.Collect(ctx, dc.errColl, dc.logger, "remote kv getting", err)

		// Don't wrap the error, as it will get annotated.
		return nil, false, err
	}

	return inf, ok, nil
}

// info is a single DNS client and server information record.
type info struct {
	ClientIP netip.Addr `json:"client_ip"`

	DeviceID        agd.DeviceID        `json:"device_id"`
	ProfileID       agd.ProfileID       `json:"profile_id"`
	ServerGroupName agd.ServerGroupName `json:"server_group_name"`
	ServerName      agd.ServerName      `json:"server_name"`
	ServerType      serverType          `json:"server_type"`

	NodeLocation string `json:"node_location"`
	NodeName     string `json:"node_name"`
	Protocol     string `json:"protocol"`
	TLSCurveID   string `json:"tls_curve_id"`
}
