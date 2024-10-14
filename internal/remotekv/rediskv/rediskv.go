// Package rediskv contains implementation of [remotekv.Interface] for Redis.
package rediskv

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/gomodule/redigo/redis"
)

// Redis-related constants.
const (
	// MinTTL is the minimum TTL that can be set when setting any TTL.
	MinTTL = 1 * time.Millisecond
)

// RedisKV is a Redis implementation of the [remotekv.Interface] interface.
//
// Note that Redis, by convention, uses colon ":" character to delimit key
// namespaces.  This process should be handled by [remotekv.KeyNamespace].
//
// TODO(a.garipov):  Find ways of testing.
type RedisKV struct {
	metrics Metrics
	pool    *redis.Pool
	ttl     time.Duration
}

// RedisKVConfig is the configuration for the Redis-based [remotekv.Interface]
// implementation.  All fields must not be empty.
type RedisKVConfig struct {
	// Metrics is used for the collection of the Redis KV statistics.
	Metrics Metrics

	// Addr is the address of the Redis server.
	Addr *netutil.HostPort

	// MaxActive is the maximum number of connections allocated by the Redis
	// connection-pool at a given time.  When zero, there is no limit on the
	// number of connections in the pool.
	MaxActive int

	// MaxIdle is the maximum number of idle connections in the pool.  When
	// zero, there is no limit.
	MaxIdle int

	// IdleTimeout is the time after remaining, idle connection will be closed.
	IdleTimeout time.Duration

	// TTL defines, after how much time the keys should expire.  TTL must be
	// greater than or equal to [MinTTL], since that's the minimum expiration
	// allowed by Redis.
	TTL time.Duration
}

// NewRedisKV returns a new *RedisKV.  c must not be nil.
func NewRedisKV(c *RedisKVConfig) (kv *RedisKV) {
	// dialNoDNSCache dials addr using the Go resolver that ignores DNS TTL
	// values.
	//
	// TODO(a.garipov):  Extract all common redis logic to golibs.
	dialNoDNSCache := func(ctx context.Context) (conn redis.Conn, err error) {
		r := &net.Resolver{
			PreferGo: true,
		}
		ips, err := r.LookupNetIP(ctx, "ip", c.Addr.Host)
		if err != nil {
			return nil, fmt.Errorf("looking up: %w", err)
		} else if len(ips) == 0 {
			panic(errors.Error(
				"stdlib contract violation: net.Resolver.LookupNetIP: 0 ips with no error",
			))
		}

		port := c.Addr.Port
		addrPort := netip.AddrPortFrom(ips[0], port)
		conn, err = redis.DialContext(ctx, "tcp", addrPort.String())
		if err != nil {
			return nil, fmt.Errorf("dialing first of %q and port %d: %w", ips, port, err)
		}

		return conn, nil
	}

	return &RedisKV{
		metrics: c.Metrics,
		pool: &redis.Pool{
			DialContext:  dialNoDNSCache,
			TestOnBorrow: checkConnRole,
			MaxIdle:      c.MaxIdle,
			MaxActive:    c.MaxActive,
			IdleTimeout:  c.IdleTimeout,
			Wait:         true,
		},
		ttl: c.TTL,
	}
}

// checkConnRole returns an error if the connection is invalid or if the cluster
// is in slave mode.
func checkConnRole(c redis.Conn, _ time.Time) (err error) {
	defer func() { err = errors.Annotate(err, "testing conn: %w") }()

	val, err := redis.Strings(c.Do(redisCmdROLE))
	if err != nil {
		return fmt.Errorf("testing conn: %w", err)
	}

	if l := len(val); l < 1 {
		return fmt.Errorf("want at least one value, got %d", l)
	}

	role := val[0]
	if role != redisRequiredRole {
		return fmt.Errorf("want role %q, got %q", redisRequiredRole, role)
	}

	return nil
}

// Redis commands, parameters, and other constants.
const (
	redisCmdGET  = "GET"
	redisCmdROLE = "ROLE"
	redisCmdSET  = "SET"

	redisParamMs = "PX"

	redisRequiredRole = "master"
)

// type check
var _ remotekv.Interface = (*RedisKV)(nil)

// Get implements the [remotekv.Interface] interface for *RedisKV.
func (kv *RedisKV) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	defer func() { err = errors.Annotate(err, "getting %q: %w", key) }()

	defer func() {
		// #nosec G115 -- Assume that pool.ActiveCount is always non-negative.
		kv.metrics.UpdateMetrics(ctx, uint(kv.pool.ActiveCount()), err == nil)
	}()

	c, err := kv.pool.GetContext(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("getting from pool: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, c.Close()) }()

	val, err = redis.Bytes(c.Do(redisCmdGET, key))
	switch {
	case err == nil:
		return val, true, nil
	case errors.Is(err, redis.ErrNil):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("get command: %w", err)
	}
}

// Set implements the [remotekv.Interface] interface for *RedisKV.
func (kv *RedisKV) Set(ctx context.Context, key string, val []byte) (err error) {
	defer func() { err = errors.Annotate(err, "setting %q: %w", key) }()

	defer func() {
		// #nosec G115 -- Assume that pool.ActiveCount is always non-negative.
		kv.metrics.UpdateMetrics(ctx, uint(kv.pool.ActiveCount()), err == nil)
	}()

	c, err := kv.pool.GetContext(ctx)
	if err != nil {
		return fmt.Errorf("getting from pool: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, c.Close()) }()

	_, err = c.Do(redisCmdSET, key, val, redisParamMs, kv.ttl.Milliseconds())
	if err != nil {
		return fmt.Errorf("set command: %w", err)
	}

	return nil
}
