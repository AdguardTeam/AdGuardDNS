package filterstorage_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterstorage"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testStandardAccessStorage is the mock implementation of the
// [filterstorage.StandardAccessStorage] interface for tests.
//
// TODO(e.burkov):  Move to agdtest.
type testStandardAccessStorage struct {
	OnConfig func(ctx context.Context) (conf *access.StandardBlockerConfig, err error)
}

// type check
var _ filterstorage.StandardAccessStorage = (*testStandardAccessStorage)(nil)

// Config implements the [filterstorage.StandardAccessStorage] interface for
// *testStandardAccessStorage.
func (s *testStandardAccessStorage) Config(
	ctx context.Context,
) (conf *access.StandardBlockerConfig, err error) {
	return s.OnConfig(ctx)
}

// testStandardSetter is the mock implementation of the [access.StandardSetter]
// interface for tests.
//
// TODO(e.burkov):  Move to agdtest.
type testStandardSetter struct {
	OnSetConfig func(conf *access.StandardBlockerConfig)
}

// type check
var _ access.StandardSetter = (*testStandardSetter)(nil)

// SetConfig implements the [access.StandardSetter] interface for
// *testStandardSetter.
func (s *testStandardSetter) SetConfig(conf *access.StandardBlockerConfig) {
	s.OnSetConfig(conf)
}

// panicSetter is the mock implementation of the [access.StandardSetter]
// interface for tests that panics on any call.
var panicSetter = &testStandardSetter{
	OnSetConfig: func(conf *access.StandardBlockerConfig) { panic("should not be called") },
}

func TestStandardAccess(t *testing.T) {
	t.Parallel()

	testConf := &access.StandardBlockerConfig{
		AllowedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		BlockedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")},
		AllowedASN:  []geoip.ASN{10},
		BlockedASN:  []geoip.ASN{20},
		BlocklistDomainRules: []string{
			"blocked.std.test",
			"@@allowed.std.test",
		},
	}

	errStorage := &testStandardAccessStorage{
		OnConfig: func(_ context.Context) (conf *access.StandardBlockerConfig, err error) {
			return nil, assert.AnError
		},
	}
	okStorage := &testStandardAccessStorage{
		OnConfig: func(_ context.Context) (conf *access.StandardBlockerConfig, err error) {
			return testConf, nil
		},
	}

	pt := testutil.PanicT{}
	emptySetter := &testStandardSetter{
		OnSetConfig: func(conf *access.StandardBlockerConfig) { require.Empty(pt, conf) },
	}
	testSetter := &testStandardSetter{
		OnSetConfig: func(conf *access.StandardBlockerConfig) { require.Equal(pt, testConf, conf) },
	}

	testCases := []struct {
		storage     filterstorage.StandardAccessStorage
		setter      access.StandardSetter
		wantRefrErr error
		name        string
	}{{
		storage:     okStorage,
		setter:      testSetter,
		wantRefrErr: nil,
		name:        "success",
	}, {
		storage:     filterstorage.EmptyStandardAccessStorage{},
		setter:      emptySetter,
		wantRefrErr: nil,
		name:        "empty",
	}, {
		storage:     errStorage,
		setter:      panicSetter,
		wantRefrErr: assert.AnError,
		name:        "error",
	}}

	for _, tc := range testCases {
		setter := &testStandardSetter{
			// Use empty setter to ensure that nothing stored in cache.
			OnSetConfig: emptySetter.OnSetConfig,
		}

		cacheDir := t.TempDir()
		filtertest.CreateFilterCacheDirs(t, cacheDir)

		newCtx := testutil.ContextWithTimeout(t, filtertest.Timeout)
		sa, newErr := filterstorage.NewStandardAccess(newCtx, &filterstorage.StandardAccessConfig{
			Logger:     filtertest.Logger,
			BaseLogger: filtertest.Logger,
			Getter:     tc.storage,
			Setter:     setter,
			CacheDir:   cacheDir,
		})
		require.NoError(t, newErr)

		setter.OnSetConfig = tc.setter.SetConfig

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			err := sa.Refresh(ctx)
			require.ErrorIs(t, err, tc.wantRefrErr)
		})
	}
}

func TestStandardAccess_cache(t *testing.T) {
	t.Parallel()

	testConf := &access.StandardBlockerConfig{
		AllowedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		BlockedNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")},
		AllowedASN:  []geoip.ASN{10},
		BlockedASN:  []geoip.ASN{20},
		BlocklistDomainRules: []string{
			"blocked.std.test",
			"@@allowed.std.test",
		},
	}

	pt := testutil.PanicT{}
	testSetter := &testStandardSetter{
		OnSetConfig: func(conf *access.StandardBlockerConfig) {
			require.Equal(pt, testConf, conf)
		},
	}
	emptySetter := &testStandardSetter{
		OnSetConfig: func(conf *access.StandardBlockerConfig) {
			require.Empty(pt, conf)
		},
	}

	testCases := []struct {
		setter     access.StandardSetter
		wantErrMsg string
		name       string
	}{{
		setter:     testSetter,
		wantErrMsg: "",
		name:       "success",
	}, {
		setter: panicSetter,
		wantErrMsg: "malformed cache: schema_version: out of range: " +
			"must be no less than 1, got 0",
		name: "bad_version",
	}, {
		setter:     emptySetter,
		wantErrMsg: "",
		name:       "non-existent",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
			_, err := filterstorage.NewStandardAccess(ctx, &filterstorage.StandardAccessConfig{
				Logger:     filtertest.Logger,
				BaseLogger: filtertest.Logger,
				Getter:     filterstorage.EmptyStandardAccessStorage{},
				Setter:     tc.setter,
				CacheDir:   filepath.Join("./testdata", t.Name()),
			})
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
