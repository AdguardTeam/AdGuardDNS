// Package rediskv contains implementation of [remotekv.Interface] for Redis.
package rediskv

import (
	"context"
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/redisutil"
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
type RedisKV struct {
	pool redisutil.Pool
	ttl  time.Duration
}

// RedisKVConfig is the configuration for the Redis-based [remotekv.Interface]
// implementation.  All fields must not be empty.
type RedisKVConfig struct {
	// Pool maintains a pool of Redis connections. It must not be nil.
	Pool redisutil.Pool

	// TTL defines, after how much time the keys should expire.  TTL must be
	// greater than or equal to [MinTTL], since that's the minimum expiration
	// allowed by Redis.
	TTL time.Duration
}

// NewRedisKV returns a new *RedisKV.  c must not be nil.
func NewRedisKV(c *RedisKVConfig) (kv *RedisKV) {
	return &RedisKV{
		ttl:  c.TTL,
		pool: c.Pool,
	}
}

// type check
var _ remotekv.Interface = (*RedisKV)(nil)

// Get implements the [remotekv.Interface] interface for *RedisKV.
func (kv *RedisKV) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	defer func() { err = errors.Annotate(err, "getting %q: %w", key) }()

	c, err := kv.pool.Get(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("getting from pool: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, c.Close()) }()

	val, err = redis.Bytes(c.Do(redisutil.CmdGET, key))
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

	c, err := kv.pool.Get(ctx)
	if err != nil {
		return fmt.Errorf("getting from pool: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, c.Close()) }()

	_, err = c.Do(redisutil.CmdSET, key, val, redisutil.ParamPX, kv.ttl.Milliseconds())
	if err != nil {
		return fmt.Errorf("set command: %w", err)
	}

	return nil
}
