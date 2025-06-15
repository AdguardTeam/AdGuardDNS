package rediskv_test

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/rediskv"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/redisutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPortEnvVarName is the environment variable name the presence and value of
// which define whether to run depending tests and on which port Redis server is
// running.
const testPortEnvVarName = "TEST_REDIS_PORT"

// Redis pool configuration constants for common tests.
const (
	testIdleTimeout     = 30 * time.Second
	testMaxConnLifetime = 30 * time.Second
	testTimeout         = 5 * time.Second

	testMaxActive = 10
	testMaxIdle   = 3

	testDBIndex = 15
)

// Test constants.
const (
	testKey   = "test_key"
	testValue = "test_value"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

// newIntegrationDialer returns a *redisutil.DefaultDialer for tests or skips
// the test if [testPortEnvVarName] is not set.  It selects a database at
// [testDBIndex] and flushes it after the test.
func newIntegrationDialer(tb testing.TB) (d *redisutil.DefaultDialer) {
	tb.Helper()

	portStr := os.Getenv(testPortEnvVarName)
	if portStr == "" {
		tb.Skipf("skipping; %s is not set", testPortEnvVarName)
	}

	port64, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(tb, err)

	d, err = redisutil.NewDefaultDialer(&redisutil.DefaultDialerConfig{
		Addr: &netutil.HostPort{
			Host: "localhost",
			Port: uint16(port64),
		},
		DBIndex: testDBIndex,
	})
	require.NoError(tb, err)

	testutil.CleanupAndRequireSuccess(tb, func() (cleanupErr error) {
		ctx := testutil.ContextWithTimeout(tb, testTimeout)
		c, cleanupErr := d.DialContext(ctx)
		require.NoError(tb, cleanupErr)
		testutil.CleanupAndRequireSuccess(tb, c.Close)

		okStr, cleanupErr := redis.String(c.Do(redisutil.CmdFLUSHDB, redisutil.ParamSYNC))
		require.NoError(tb, cleanupErr)

		assert.Equal(tb, redisutil.RespOK, okStr)

		return cleanupErr
	})

	return d
}

// newIntegrationPool returns a *redisutil.DefaultPool for tests or skips the
// test if [testPortEnvVarName] is not set.  It selects a database at
// [testDBIndex] and flushes it after the test.
func newIntegrationPool(tb testing.TB) (p *redisutil.DefaultPool) {
	tb.Helper()

	dialer := newIntegrationDialer(tb)
	p, err := redisutil.NewDefaultPool(&redisutil.DefaultPoolConfig{
		Logger:          testLogger,
		Dialer:          dialer,
		MaxConnLifetime: testMaxConnLifetime,
		IdleTimeout:     testIdleTimeout,
		MaxActive:       testMaxActive,
		MaxIdle:         testMaxIdle,
		Wait:            true,
	})
	require.NoError(tb, err)

	return p
}

// TestRedisKV_Get is a test for [rediskv.RedisKV.Get].  It requires a Redis
// server running on 127.0.0.1 and must be run with [testPortEnvVarName] set to
// running Redis server port.
func TestRedisKV_Get(t *testing.T) {
	pool := newIntegrationPool(t)
	kv := rediskv.NewRedisKV(&rediskv.RedisKVConfig{
		Pool: pool,
		TTL:  testTimeout,
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	val, ok, err := kv.Get(ctx, testKey)
	require.NoError(t, err)

	assert.False(t, ok)
	assert.Nil(t, val)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	conn, err := pool.Get(ctx)
	require.NoError(t, err)

	defer testutil.CleanupAndRequireSuccess(t, conn.Close)

	_, err = conn.Do(redisutil.CmdSET, testKey, testValue)
	require.NoError(t, err)

	ctx = testutil.ContextWithTimeout(t, testTimeout)
	val, ok, err = kv.Get(ctx, testKey)
	require.NoError(t, err)

	assert.True(t, ok)
	assert.Equal(t, []byte(testValue), val)
}

// TestRedisKV_Set is a test for [rediskv.RedisKV.Set].  It requires a Redis
// server running on 127.0.0.1 and must be run with [testPortEnvVarName] set to
// running Redis server port.
func TestRedisKV_Set(t *testing.T) {
	pool := newIntegrationPool(t)
	kv := rediskv.NewRedisKV(&rediskv.RedisKVConfig{
		Pool: pool,
		TTL:  testTimeout,
	})

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	err := kv.Set(ctx, testKey, []byte(testValue))
	require.NoError(t, err)

	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	defer testutil.CleanupAndRequireSuccess(t, conn.Close)

	val, err := redis.Bytes(conn.Do(redisutil.CmdGET, testKey))
	require.NoError(t, err)

	assert.Equal(t, []byte(testValue), val)

	// TODO(a.garipov): make it const redisutil.CMDPTTL
	ttl, err := redis.Int64(conn.Do("PTTL", testKey))
	require.NoError(t, err)

	now := time.Now()
	ttlTime := now.Add(time.Duration(ttl))
	maxTime := now.Add(testTimeout)

	assert.WithinRange(t, ttlTime, now, maxTime)
}
