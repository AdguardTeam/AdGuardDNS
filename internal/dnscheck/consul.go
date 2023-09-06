package dnscheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	cache "github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
)

// Consul KV Database Checker With TTL

// Consul is the Consul KV based DNS checker.
//
// TODO(a.garipov): Add tests.
type Consul struct {
	// mu protects cache.  Don't use an RWMutex here, since the ratio of read
	// and write access is expected to be approximately equal.
	mu    *sync.Mutex
	cache *cache.Cache

	kv       consulKV
	messages *dnsmsg.Constructor

	errColl agd.ErrorCollector

	domains      []string
	nodeLocation string
	nodeName     string

	ipv4 []netip.Addr
	ipv6 []netip.Addr
}

// ConsulConfig is the configuration structure for Consul KV based DNS checker.
// All fields must be non-empty.
type ConsulConfig struct {
	// Messages is the message constructor used to create DNS responses with
	// IPv4 and IPv6 IPs.
	Messages *dnsmsg.Constructor

	// ConsulKVURL is the URL to the Consul KV database.
	ConsulKVURL *url.URL

	// ConsulSessionURL is the URL to the Consul session API.
	ConsulSessionURL *url.URL

	// ErrColl is the error collector that is used to collect non-critical
	// errors.
	ErrColl agd.ErrorCollector

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

	// TTL defines, for how long to keep the information about a single client.
	TTL time.Duration
}

// Default cache parameters.
//
// TODO(ameshkov): Consider making configurable.
const (
	defaultCacheExp = 1 * time.Minute
	defaultCacheGC  = 1 * time.Minute
)

// NewConsul creates a new Consul KV based DNS checker.  c must be non-nil.
func NewConsul(c *ConsulConfig) (cc *Consul, err error) {
	cc = &Consul{
		mu:    &sync.Mutex{},
		cache: cache.New(defaultCacheExp, defaultCacheGC),

		messages: c.Messages,

		errColl: c.ErrColl,

		domains:      c.Domains,
		nodeLocation: c.NodeLocation,
		nodeName:     c.NodeName,

		ipv4: slices.Clone(c.IPv4),
		ipv6: slices.Clone(c.IPv6),
	}

	// TODO(e.burkov):  Validate also c.ConsulSessionURL?
	if cu, cs := c.ConsulKVURL, c.ConsulSessionURL; cu != nil && cs != nil {
		err = validateConsulURL(cu)
		if err != nil {
			return nil, fmt.Errorf("initializing consul dnscheck: %w", err)
		}

		cc.kv = &httpKV{
			url:     cu,
			sessURL: cs,
			http: agdhttp.NewClient(&agdhttp.ClientConfig{
				// TODO(ameshkov): Consider making configurable.
				Timeout: 15 * time.Second,
			}),
			// TODO(ameshkov): Consider making configurable.
			limiter: rate.NewLimiter(rate.Limit(200)/60, 1),
			ttl:     c.TTL,
		}
	} else {
		cc.kv = nopKV{}
	}

	return cc, nil
}

// type check
var _ Interface = (*Consul)(nil)

// Check implements the Interface interface for *Consul.  The context must
// contain the lowercased hostname as well as the server information.
func (cc *Consul) Check(
	ctx context.Context,
	req *dns.Msg,
	ri *agd.RequestInfo,
) (resp *dns.Msg, err error) {
	var matched bool
	defer func() {
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

	si := dnsserver.MustServerInfoFromContext(ctx)
	inf := cc.newInfo(si.Proto.String(), ri)

	cc.addToCache(randomID, inf)

	err = cc.kv.set(ctx, randomID, inf)
	if err != nil {
		agd.Collectf(ctx, cc.errColl, "dnscheck: consul setting: %w", err)
	}

	return cc.resp(ri, req)
}

// addToCache adds inf into cache using randomID as key.  It's safe for
// concurrent use.
func (cc *Consul) addToCache(randomID string, inf *info) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.cache.SetDefault(randomID, inf)
}

// newInfo returns an information record with all available data about the
// server and the request.  ri must not be nil.
func (cc *Consul) newInfo(protoStr string, ri *agd.RequestInfo) (inf *info) {
	inf = &info{
		ServerGroupName: ri.ServerGroup,
		ServerName:      ri.Server,

		Protocol:     protoStr,
		NodeLocation: cc.nodeLocation,
		NodeName:     cc.nodeName,

		ClientIP: ri.RemoteIP,
	}

	if d := ri.Device; d != nil {
		inf.DeviceID = d.ID
	}

	if p := ri.Profile; p != nil {
		inf.ProfileID = p.ID
	}

	return inf
}

// resp returns the corresponding response.
func (cc *Consul) resp(ri *agd.RequestInfo, req *dns.Msg) (resp *dns.Msg, err error) {
	qt := ri.QType

	if qt != dns.TypeA && qt != dns.TypeAAAA {
		return ri.Messages.NewMsgNODATA(req), nil
	}

	if qt == dns.TypeA {
		return cc.messages.NewIPRespMsg(req, cc.ipv4...)
	}

	return cc.messages.NewIPRespMsg(req, cc.ipv6...)
}

// type check
var _ http.Handler = (*Consul)(nil)

// ServeHTTP implements the http.Handler interface for *Consul.
func (cc *Consul) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
func (cc *Consul) serveCheckTest(ctx context.Context, w http.ResponseWriter, r *http.Request) {
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

	inf, err := cc.info(ctx, randomID)
	if errors.Is(err, errRateLimited) {
		http.Error(w, err.Error(), http.StatusTooManyRequests)

		return
	} else if err != nil {
		log.Debug("dnscheck: http req from %s: getting info: %s", raddr, err)

		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	} else if inf == nil {
		log.Debug("dnscheck: http req from %s: no info for %q", raddr, randomID)

		http.NotFound(w, r)

		return
	}

	h := w.Header()
	h.Set(httphdr.ContentType, agdhttp.HdrValApplicationJSON)
	h.Set(httphdr.AccessControlAllowOrigin, agdhttp.HdrValWildcard)

	err = json.NewEncoder(w).Encode(inf)
	if err != nil {
		agd.Collectf(ctx, cc.errColl, "dnscheck: http resp write error: %w", err)
	}
}

// errRateLimited is returned by Consul.info when the request is rate limited.
const errRateLimited errors.Error = "rate limited"

// info returns an information record by the random request ID.
func (cc *Consul) info(ctx context.Context, randomID string) (inf *info, err error) {
	defer func() {
		metrics.DNSCheckRequestTotal.With(prometheus.Labels{
			"type":  "http",
			"valid": metrics.BoolString(err == nil),
		}).Inc()
	}()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	infoVal, ok := cc.cache.Get(randomID)
	if ok {
		return infoVal.(*info), nil
	}

	inf, err = cc.kv.get(ctx, randomID)
	if err != nil {
		agd.Collectf(ctx, cc.errColl, "dnscheck: consul getting: %w", err)

		return nil, fmt.Errorf("getting from consul: %w", err)
	}

	return inf, nil
}

// info is a single DNS client and server information record.
type info struct {
	ClientIP netip.Addr `json:"client_ip"`

	DeviceID        agd.DeviceID        `json:"device_id"`
	ProfileID       agd.ProfileID       `json:"profile_id"`
	ServerGroupName agd.ServerGroupName `json:"server_group_name"`
	ServerName      agd.ServerName      `json:"server_name"`

	Protocol     string `json:"protocol"`
	NodeLocation string `json:"node_location"`
	NodeName     string `json:"node_name"`
}
