package dnscheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	cache "github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
)

// RemoteKV is the RemoteKV KV based DNS checker.
type RemoteKV struct {
	// mu protects cache.  Don't use an RWMutex here, since the ratio of read
	// and write access is expected to be approximately equal.
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
	// Messages is the message constructor used to create DNS responses with
	// IPv4 and IPv6 IPs.
	Messages *dnsmsg.Constructor

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
func NewRemoteKV(c *RemoteKVConfig) (cc *RemoteKV) {
	return &RemoteKV{
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

// Check implements the Interface interface for *RemoteKV.
func (cc *RemoteKV) Check(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (resp *dns.Msg, err error) {
	var matched bool
	defer func() {
		incErrMetrics("dns", err)

		if !matched {
			return
		}

		metrics.DNSCheckRequestTotal.With(prometheus.Labels{
			"type":  "dns",
			"valid": metrics.BoolString(err == nil),
		}).Inc()
	}()

	var randomID string
	randomID, matched, err = randomIDFromDomain(ri.Host, cc.domains)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	} else if !matched {
		// Not a dnscheck domain, just ignore the request.
		return nil, nil
	} else if randomID == "" {
		return cc.resp(ri, req)
	}

	inf := cc.newInfo(ri)
	b, err := json.Marshal(inf)
	if err != nil {
		return nil, fmt.Errorf("encoding value for key %q for remote kv: %w", randomID, err)
	}

	cc.addToCache(randomID, b)

	err = cc.kv.Set(ctx, randomID, b)
	if err != nil {
		errcoll.Collectf(ctx, cc.errColl, "dnscheck: remote kv setting: %w", err)
	}

	return cc.resp(ri, req)
}

// addToCache adds inf into cache using randomID as key.  It's safe for
// concurrent use.
func (cc *RemoteKV) addToCache(randomID string, inf []byte) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.cache.SetDefault(randomID, inf)
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
// server and the request.  ri must not be nil.
func (cc *RemoteKV) newInfo(ri *agd.RequestInfo) (inf *info) {
	g := ri.ServerGroup

	srvType := serverTypePublic
	if g.ProfilesEnabled {
		srvType = serverTypePrivate
	}

	inf = &info{
		ServerGroupName: g.Name,
		ServerName:      ri.Server,
		ServerType:      srvType,

		Protocol:     ri.Proto.String(),
		NodeLocation: cc.nodeLocation,
		NodeName:     cc.nodeName,

		ClientIP: ri.RemoteIP,
	}

	if p, d := ri.DeviceData(); p != nil {
		inf.ProfileID = p.ID
		inf.DeviceID = d.ID
	}

	return inf
}

// resp returns the corresponding response.
//
// TODO(e.burkov):  Inspect the reason for using different message constructors
// for different DNS types, and consider using only one of them.
func (cc *RemoteKV) resp(ri *agd.RequestInfo, req *dns.Msg) (resp *dns.Msg, err error) {
	qt := ri.QType

	if qt != dns.TypeA && qt != dns.TypeAAAA {
		return ri.Messages.NewRespRCode(req, dns.RcodeSuccess), nil
	}

	if qt == dns.TypeA {
		return cc.messages.NewRespIP(req, cc.ipv4...)
	}

	return cc.messages.NewRespIP(req, cc.ipv6...)
}

// type check
var _ http.Handler = (*RemoteKV)(nil)

// ServeHTTP implements the http.Handler interface for *RemoteKV.
func (cc *RemoteKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, p, raddr := r.Method, r.URL.Path, r.RemoteAddr
	log.Debug("dnscheck: http req %s %s from %s", m, p, raddr)
	defer log.Debug("dnscheck: finished http req %s %s from %s", m, p, raddr)

	// TODO(a.garipov): Put this into constant here and in package dnssvc.
	if r.URL.Path == "/dnscheck/test" {
		cc.serveCheckTest(r.Context(), w, r)

		return
	}

	http.NotFound(w, r)
}

// serveCheckTest serves the client DNS check API.
//
// TODO(a.garipov): Refactor this and other HTTP handlers to return wrapped
// errors and centralize the error handling.
func (cc *RemoteKV) serveCheckTest(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	raddr := r.RemoteAddr

	name, err := netutil.SplitHost(r.Host)
	if err != nil {
		log.Debug("dnscheck: http req from %s: bad host %q: %s", raddr, r.Host, err)

		http.NotFound(w, r)

		return
	}

	randomID, matched, err := randomIDFromDomain(name, cc.domains)
	if err != nil {
		log.Debug("dnscheck: http req from %s: id: %s", raddr, err)

		http.NotFound(w, r)

		return
	} else if !matched || randomID == "" {
		// We expect dnscheck requests to have a unique ID in the domain name.
		log.Debug("dnscheck: http req from %s: bad domain %q", raddr, name)

		http.NotFound(w, r)

		return
	}

	inf, ok, err := cc.info(ctx, randomID)
	// TODO(s.chzhen):  Use error interface instead of error value.
	if errors.Is(err, consulkv.ErrRateLimited) {
		http.Error(w, err.Error(), http.StatusTooManyRequests)

		return
	} else if err != nil {
		log.Debug("dnscheck: http req from %s: getting info: %s", raddr, err)

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	} else if !ok {
		log.Debug("dnscheck: http req from %s: no info for %q", raddr, randomID)

		http.NotFound(w, r)

		return
	}

	h := w.Header()
	h.Set(httphdr.ContentType, agdhttp.HdrValApplicationJSON)
	h.Set(httphdr.AccessControlAllowOrigin, agdhttp.HdrValWildcard)

	_, err = w.Write(inf)
	if err != nil {
		errcoll.Collectf(ctx, cc.errColl, "dnscheck: http resp write error: %w", err)
	}
}

// info returns an information record by the random request ID.
func (cc *RemoteKV) info(ctx context.Context, randomID string) (inf []byte, ok bool, err error) {
	defer func() {
		metrics.DNSCheckRequestTotal.With(prometheus.Labels{
			"type":  "http",
			"valid": metrics.BoolString(err == nil),
		}).Inc()

		incErrMetrics("http", err)
	}()

	defer func() { err = errors.Annotate(err, "getting from remote kv: %w") }()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	infoVal, ok := cc.cache.Get(randomID)
	if ok {
		return infoVal.([]byte), true, nil
	}

	inf, ok, err = cc.kv.Get(ctx, randomID)
	if err != nil {
		errcoll.Collectf(ctx, cc.errColl, "dnscheck: remote kv getting: %w", err)

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

	Protocol     string `json:"protocol"`
	NodeLocation string `json:"node_location"`
	NodeName     string `json:"node_name"`
}
