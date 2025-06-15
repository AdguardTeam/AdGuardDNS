package tlsconfig_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testIndexName is the name of the index file for tests.
	testIndexName = "index.json"

	// testTicketName is a name of a TLS session ticket that must be
	// handled successfully.
	testTicketName tlsconfig.SessionTicketName = "ticket1"
)

// testTicketStorage is a test implementation of the [tlsconfig.TicketStorage]
// interface.
type testTicketStorage struct {
	onTickets func(ctx context.Context) (named tlsconfig.NamedTickets, err error)
}

// type check
var _ tlsconfig.TicketStorage = (*testTicketStorage)(nil)

// Tickets implements the [tlsconfig.TicketStorage] interface for
// *testTicketStorage.
func (s *testTicketStorage) Tickets(ctx context.Context) (named tlsconfig.NamedTickets, err error) {
	return s.onTickets(ctx)
}

func TestRemoteTicketDB_Paths(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		onTickets   func(ctx context.Context) (named tlsconfig.NamedTickets, err error)
		wantErrMsg  string
		wantTickets []tlsconfig.SessionTicketName
	}{{
		name: "success",
		onTickets: func(_ context.Context) (named tlsconfig.NamedTickets, err error) {
			return tlsconfig.NamedTickets{
				testTicketName: tlsconfig.SessionTicket{},
			}, nil
		},
		wantErrMsg:  "",
		wantTickets: []tlsconfig.SessionTicketName{testTicketName},
	}, {
		name: "empty",
		onTickets: func(_ context.Context) (named tlsconfig.NamedTickets, err error) {
			return nil, nil
		},
		wantErrMsg: "refreshing ticket database: received tickets: " +
			errors.ErrEmptyValue.Error(),
		wantTickets: nil,
	}, {
		name: "storage_error",
		onTickets: func(ctx context.Context) (named tlsconfig.NamedTickets, err error) {
			return nil, assert.AnError
		},
		wantErrMsg: "refreshing ticket database: retrieving tickets: " +
			assert.AnError.Error(),
		wantTickets: nil,
	}, {
		name: "reserved_name_error",
		onTickets: func(_ context.Context) (named tlsconfig.NamedTickets, err error) {
			return tlsconfig.NamedTickets{
				testIndexName: tlsconfig.SessionTicket{},
			}, nil
		},
		wantErrMsg: `refreshing ticket database: writing ticket "` + testIndexName +
			`": name: ` + errors.ErrBadEnumValue.Error() + `: "` + testIndexName +
			`"; reserved for index`,
		wantTickets: nil,
	}, {
		name: "has_valid",
		onTickets: func(_ context.Context) (named tlsconfig.NamedTickets, err error) {
			return tlsconfig.NamedTickets{
				testTicketName: tlsconfig.SessionTicket{},
				testIndexName:  tlsconfig.SessionTicket{},
			}, nil
		},
		wantErrMsg: `refreshing ticket database: writing ticket "` + testIndexName +
			`": name: ` + errors.ErrBadEnumValue.Error() + `: "` + testIndexName +
			`"; reserved for index`,
		wantTickets: []tlsconfig.SessionTicketName{testTicketName},
	}}

	for _, tc := range testCases {
		tempDir := t.TempDir()
		conf := &tlsconfig.RemoteTicketDBConfig{
			Logger: testLogger,
			Storage: &testTicketStorage{
				onTickets: tc.onTickets,
			},
			CacheDirPath:  tempDir,
			IndexFileName: testIndexName,
			Clock:         timeutil.SystemClock{},
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, err := tlsconfig.NewRemoteTicketDB(conf)
			require.NoError(t, err)

			ctx := testutil.ContextWithTimeout(t, testTimeout)
			paths, err := db.Paths(ctx)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			assertTicketPaths(t, paths, tc.wantTickets)
			if len(tc.wantTickets) > 0 {
				assertIndexConsistency(t, tempDir, testIndexName, tc.wantTickets)
			}
		})
	}
}

// TODO(e.burkov):  Enhance the test to cover cases of invalid index files.
func TestRemoteTicketDB_Paths_initialError(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	want := []tlsconfig.SessionTicketName{testTicketName}
	index := &tlsconfig.StoredIndex{
		Tickets: tlsconfig.IndexedTickets{},
		Version: tlsconfig.TicketIndexVersion,
	}
	for i, name := range want {
		tick := tlsconfig.SessionTicket{}
		binary.BigEndian.PutUint32(tick[:], uint32(i))
		err := os.WriteFile(filepath.Join(tempDir, string(name)), tick[:], 0o600)
		require.NoError(t, err)

		index.Tickets[name] = &tlsconfig.IndexedTicket{
			LastUpdate: time.Now(),
		}
	}

	indexData := &bytes.Buffer{}
	err := json.NewEncoder(indexData).Encode(index)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, testIndexName), indexData.Bytes(), 0o600)
	require.NoError(t, err)

	assertIndexConsistency(t, tempDir, testIndexName, want)

	db, err := tlsconfig.NewRemoteTicketDB(&tlsconfig.RemoteTicketDBConfig{
		Logger: testLogger,
		Storage: &testTicketStorage{
			onTickets: func(_ context.Context) (_ tlsconfig.NamedTickets, err error) {
				return nil, assert.AnError
			},
		},
		CacheDirPath:  tempDir,
		IndexFileName: testIndexName,
		Clock:         timeutil.SystemClock{},
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	paths, err := db.Paths(ctx)
	require.ErrorIs(t, err, assert.AnError)

	assertTicketPaths(t, paths, want)
}

// assertTicketPaths checks that base names of the paths returned by db are the
// same as want.
func assertTicketPaths(tb testing.TB, got []string, want []tlsconfig.SessionTicketName) {
	tb.Helper()

	if len(want) == 0 {
		require.Empty(tb, got)

		return
	}

	require.Len(tb, got, len(want))

	for _, p := range got {
		name := filepath.Base(p)
		assert.Contains(tb, want, tlsconfig.SessionTicketName(name))
	}
}

// assertIndexConsistency checks that the index file is consistent with the
// expected set of tickets and with contents of the cache directory.
func assertIndexConsistency(
	tb testing.TB,
	cacheDir string,
	indexName string,
	want []tlsconfig.SessionTicketName,
) {
	tb.Helper()

	indexPath := filepath.Join(cacheDir, indexName)
	f, err := os.Open(indexPath)
	require.NoError(tb, err)

	var index tlsconfig.StoredIndex
	err = json.NewDecoder(f).Decode(&index)
	require.NoError(tb, err)

	names := slices.Sorted(maps.Keys(index.Tickets))
	require.Equal(tb, want, names)

	for _, name := range names {
		var info fs.FileInfo
		info, err = os.Stat(filepath.Join(cacheDir, string(name)))
		require.NoError(tb, err)

		assert.LessOrEqual(tb, info.ModTime(), index.Tickets[name].LastUpdate)
	}
}
