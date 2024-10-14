package cmd

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/rediskv"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
)

// checkConfig is the DNS server checking configuration.
type checkConfig struct {
	// RemoteKV is remote key-value store configuration for DNS server checking.
	RemoteKV *remoteKVConfig `yaml:"kv"`

	// Domains are the domain names used for DNS server checking.
	Domains []string `yaml:"domains"`

	// NodeLocation is the location of this server node.
	NodeLocation string `yaml:"node_location"`

	// NodeName is the name of this server node.
	NodeName string `yaml:"node_name"`

	// IPv4 is the list of IPv4 addresses to respond with for A queries to
	// subdomains of Domain.
	IPv4 []netip.Addr `yaml:"ipv4"`

	// IPv6 is the list of IPv6 addresses to respond with for AAAA queries to
	// subdomains of Domain.
	IPv6 []netip.Addr `yaml:"ipv6"`
}

// toInternal converts c to the DNS server check configuration for the DNS
// server.  c must be valid.
func (c *checkConfig) toInternal(
	envs *environment,
	messages *dnsmsg.Constructor,
	errColl errcoll.Interface,
	namespace string,
	reg prometheus.Registerer,
) (conf *dnscheck.RemoteKVConfig, err error) {
	kv, err := newDNSCheckKV(c, envs, namespace, reg)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	domains := make([]string, len(c.Domains))
	for i, d := range c.Domains {
		domains[i] = strings.ToLower(d)
	}

	return &dnscheck.RemoteKVConfig{
		Messages:     messages,
		RemoteKV:     kv,
		ErrColl:      errColl,
		Domains:      domains,
		NodeLocation: c.NodeLocation,
		NodeName:     c.NodeName,
		IPv4:         c.IPv4,
		IPv6:         c.IPv6,
	}, nil
}

// maxRespSize is the maximum size of response from Consul key-value storage.
const maxRespSize = 1 * datasize.MB

// keyNamespaceCheck is the namespace added to the keys of DNS check.  See
// [remotekv.KeyNamespace].
const keyNamespaceCheck = "check"

// newDNSCheckKV returns a new properly initialized remote key-value storage.
func newDNSCheckKV(
	conf *checkConfig,
	envs *environment,
	namespace string,
	reg prometheus.Registerer,
) (kv remotekv.Interface, err error) {
	if conf.RemoteKV.Type == kvModeRedis {
		var redisKVMtrc rediskv.Metrics
		redisKVMtrc, err = metrics.NewRedisKV(namespace, reg)
		if err != nil {
			return nil, fmt.Errorf("registering redis kv metrics: %w", err)
		}

		kv := rediskv.NewRedisKV(&rediskv.RedisKVConfig{
			Metrics: redisKVMtrc,
			Addr: &netutil.HostPort{
				Host: envs.RedisAddr,
				Port: envs.RedisPort,
			},
			MaxActive:   envs.RedisMaxActive,
			MaxIdle:     envs.RedisMaxIdle,
			IdleTimeout: envs.RedisIdleTimeout.Duration,
			TTL:         conf.RemoteKV.TTL.Duration,
		})

		return remotekv.NewKeyNamespace(&remotekv.KeyNamespaceConfig{
			KV:     kv,
			Prefix: fmt.Sprintf("%s:%s:", envs.RedisKeyPrefix, keyNamespaceCheck),
		}), nil
	}

	consulKVURL := envs.ConsulDNSCheckKVURL
	consulSessionURL := envs.ConsulDNSCheckSessionURL
	if consulKVURL != nil && consulSessionURL != nil {
		kv, err = consulkv.NewKV(&consulkv.Config{
			URL:        &consulKVURL.URL,
			SessionURL: &consulSessionURL.URL,
			Client: agdhttp.NewClient(&agdhttp.ClientConfig{
				// TODO(ameshkov): Consider making configurable.
				Timeout: 15 * time.Second,
			}),
			// TODO(ameshkov): Consider making configurable.
			Limiter:     rate.NewLimiter(rate.Limit(200)/60, 1),
			TTL:         conf.RemoteKV.TTL.Duration,
			MaxRespSize: maxRespSize,
		})
		if err != nil {
			return nil, fmt.Errorf("initializing consul dnscheck: %w", err)
		}
	} else {
		kv = remotekv.Empty{}
	}

	return kv, nil
}

// type check
var _ validator = (*checkConfig)(nil)

// validate implements the [validator] interface for *checkConfig.
func (c *checkConfig) validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	notEmptyParams := container.KeyValues[string, string]{{
		Key:   "node_location",
		Value: c.NodeLocation,
	}, {
		Key:   "node_name",
		Value: c.NodeName,
	}}

	for _, kv := range notEmptyParams {
		if kv.Value == "" {
			return fmt.Errorf("%s: %w", kv.Key, errors.ErrEmptyValue)
		}
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("domains: %w", errors.ErrEmptyValue)
	}

	err = validateNonNilIPs(c.IPv4, netutil.AddrFamilyIPv4)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = validateNonNilIPs(c.IPv6, netutil.AddrFamilyIPv6)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = c.RemoteKV.validate()
	if err != nil {
		return fmt.Errorf("kv: %w", err)
	}

	return nil
}

// validateNonNilIPs returns an error if ips is empty or had IP addresses of
// incorrect protocol version.
//
// TODO(a.garipov): Merge with [validateAddrs].
func validateNonNilIPs(ips []netip.Addr, fam netutil.AddrFamily) (err error) {
	if len(ips) == 0 {
		return fmt.Errorf("no %s", fam)
	}

	// Assume that since ips are parsed from YAML, they are valid.

	var checkProto func(ip netip.Addr) (ok bool)
	switch fam {
	case netutil.AddrFamilyIPv4:
		checkProto = netip.Addr.Is4
	case netutil.AddrFamilyIPv6:
		checkProto = netip.Addr.Is6
	default:
		panic(fmt.Errorf("agdnet: unsupported addr fam %s", fam))
	}

	for i, ip := range ips {
		if !checkProto(ip) {
			return fmt.Errorf("%s: address %q at index %d: incorrect protocol", fam, ip, i)
		}
	}

	return nil
}

// DNSCheck key-value database modes.
const (
	kvModeConsul = "consul"
	kvModeRedis  = "redis"
)

// remoteKVConfig is remote key-value store configuration for DNS server
// checking.
type remoteKVConfig struct {
	// Type defines the type of remote key-value store.  Allowed values are
	// [kvModeConsul] and [kvModeRedis].
	Type string `yaml:"type"`

	// TTL defines, for how long to keep the information about a single client.
	TTL timeutil.Duration `yaml:"ttl"`
}

// type check
var _ validator = (*remoteKVConfig)(nil)

// validate implements the [validator] interface for *remoteKVConfig.
func (c *remoteKVConfig) validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	ttl := c.TTL

	switch c.Type {
	case kvModeConsul:
		if ttl.Duration < consulkv.MinTTL || ttl.Duration > consulkv.MaxTTL {
			return fmt.Errorf(
				"ttl: %w: must be between %s and %s; got %s",
				errors.ErrOutOfRange,
				consulkv.MinTTL,
				consulkv.MaxTTL,
				ttl,
			)
		}
	case kvModeRedis:
		if ttl.Duration < rediskv.MinTTL {
			return fmt.Errorf(
				"ttl: %w: must be greater than or equal to %s got %s",
				errors.ErrOutOfRange,
				rediskv.MinTTL,
				ttl,
			)
		}
	case "":
		return fmt.Errorf("type: %w", errors.ErrEmptyValue)
	default:
		return fmt.Errorf("type: %q: %w", c.Type, errors.ErrBadEnumValue)
	}

	return nil
}
