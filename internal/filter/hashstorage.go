package filter

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/prometheus/client_golang/prometheus"
)

// Hash Storage

// Hash and hash part length constants.
const (
	// hashPrefixLen is the length of the prefix of the hash of the filtered
	// hostname.
	hashPrefixLen = 2

	// HashPrefixEncLen is the encoded length of the hash prefix.  Two text
	// bytes per one binary byte.
	HashPrefixEncLen = hashPrefixLen * 2

	// hashLen is the length of the whole hash of the checked hostname.
	hashLen = sha256.Size

	// hashSuffixLen is the length of the suffix of the hash of the filtered
	// hostname.
	hashSuffixLen = hashLen - hashPrefixLen

	// hashEncLen is the encoded length of the hash.  Two text bytes per one
	// binary byte.
	hashEncLen = hashLen * 2

	// legacyHashPrefixEncLen is the encoded length of a legacy hash.
	legacyHashPrefixEncLen = 8
)

// hashPrefix is the type of the 2-byte prefix of a full 32-byte SHA256 hash of
// a host being checked.
type hashPrefix [hashPrefixLen]byte

// hashSuffix is the type of the 30-byte suffix of a full 32-byte SHA256 hash of
// a host being checked.
type hashSuffix [hashSuffixLen]byte

// HashStorage is a storage for hashes of the filtered hostnames.
type HashStorage struct {
	// mu protects hashSuffixes.
	mu           *sync.RWMutex
	hashSuffixes map[hashPrefix][]hashSuffix

	// refr contains data for refreshing the filter.
	refr *refreshableFilter

	refrWorker *agd.RefreshWorker
}

// HashStorageConfig is the configuration structure for a *HashStorage.
type HashStorageConfig struct {
	// URL is the URL used to update the filter.
	URL *url.URL

	// ErrColl is used to collect non-critical and rare errors.
	ErrColl agd.ErrorCollector

	// ID is the ID of this hash storage for logging and error reporting.
	ID agd.FilterListID

	// CachePath is the path to the file containing the cached filtered
	// hostnames, one per line.
	CachePath string

	// RefreshIvl is the refresh interval.
	RefreshIvl time.Duration
}

// NewHashStorage returns a new hash storage containing hashes of all hostnames.
func NewHashStorage(c *HashStorageConfig) (hs *HashStorage, err error) {
	hs = &HashStorage{
		mu:           &sync.RWMutex{},
		hashSuffixes: map[hashPrefix][]hashSuffix{},
		refr: &refreshableFilter{
			http: agdhttp.NewClient(&agdhttp.ClientConfig{
				Timeout: defaultTimeout,
			}),
			url:        c.URL,
			id:         c.ID,
			cachePath:  c.CachePath,
			typ:        "hash storage",
			refreshIvl: c.RefreshIvl,
		},
	}

	// Do not set this in the literal above, since hs is nil there.
	hs.refr.resetRules = hs.resetHosts

	refrWorker := agd.NewRefreshWorker(&agd.RefreshWorkerConfig{
		Context: func() (ctx context.Context, cancel context.CancelFunc) {
			return context.WithTimeout(context.Background(), defaultTimeout)
		},
		Refresher:           hs,
		ErrColl:             c.ErrColl,
		Name:                string(c.ID),
		Interval:            c.RefreshIvl,
		RefreshOnShutdown:   false,
		RoutineLogsAreDebug: false,
	})

	hs.refrWorker = refrWorker

	err = hs.refresh(context.Background(), true)
	if err != nil {
		return nil, fmt.Errorf("initializing %s: %w", c.ID, err)
	}

	return hs, nil
}

// hashes returns all hashes starting with the given prefixes, if any.  The
// resulting slice shares storage for all underlying strings.
//
// TODO(a.garipov): This currently doesn't take duplicates into account.
func (hs *HashStorage) hashes(hps []hashPrefix) (hashes []string) {
	if len(hps) == 0 {
		return nil
	}

	hs.mu.RLock()
	defer hs.mu.RUnlock()

	// First, calculate the number of hashes to allocate the buffer.
	l := 0
	for _, hp := range hps {
		hashSufs := hs.hashSuffixes[hp]
		l += len(hashSufs)
	}

	// Then, allocate the buffer of the appropriate size and write all hashes
	// into one big buffer and slice it into separate strings to make the
	// garbage collector's work easier.  This assumes that all references to
	// this buffer will become unreachable at the same time.
	//
	// The fact that we iterate over the map twice shouldn't matter, since we
	// assume that len(hps) will be below 5 most of the time.
	b := &strings.Builder{}
	b.Grow(l * hashEncLen)

	// Use a buffer and write the resulting buffer into b directly instead of
	// using hex.NewEncoder, because that seems to incur a significant
	// performance hit.
	var buf [hashEncLen]byte
	for _, hp := range hps {
		hashSufs := hs.hashSuffixes[hp]
		for _, suf := range hashSufs {
			// Slicing is safe here, since the contents of hp and suf are being
			// encoded.

			// nolint:looppointer
			hex.Encode(buf[:], hp[:])
			// nolint:looppointer
			hex.Encode(buf[HashPrefixEncLen:], suf[:])
			_, _ = b.Write(buf[:])
		}
	}

	s := b.String()
	hashes = make([]string, 0, l)
	for i := 0; i < l; i++ {
		hashes = append(hashes, s[i*hashEncLen:(i+1)*hashEncLen])
	}

	return hashes
}

// loadHashSuffixes returns hash suffixes for the given prefix.  It is safe for
// concurrent use.
func (hs *HashStorage) loadHashSuffixes(hp hashPrefix) (sufs []hashSuffix, ok bool) {
	hs.mu.RLock()
	defer hs.mu.RUnlock()

	sufs, ok = hs.hashSuffixes[hp]

	return sufs, ok
}

// hashMatches returns true if the host matches one of the hashes.
func (hs *HashStorage) hashMatches(host string) (ok bool) {
	sum := sha256.Sum256([]byte(host))
	hp := hashPrefix{sum[0], sum[1]}

	var buf [hashLen]byte
	hashSufs, ok := hs.loadHashSuffixes(hp)
	if !ok {
		return false
	}

	copy(buf[:], hp[:])
	for _, suf := range hashSufs {
		// Slicing is safe here, because we make a copy.

		// nolint:looppointer
		copy(buf[hashPrefixLen:], suf[:])
		if buf == sum {
			return true
		}
	}

	return false
}

// hashPrefixesFromStr returns hash prefixes from a dot-separated string.
func hashPrefixesFromStr(prefixesStr string) (hashPrefixes []hashPrefix, err error) {
	if prefixesStr == "" {
		return nil, nil
	}

	prefixSet := stringutil.NewSet()
	prefixStrs := strings.Split(prefixesStr, ".")
	for _, s := range prefixStrs {
		if len(s) != HashPrefixEncLen {
			// Some legacy clients send eight-character hashes instead of
			// four-character ones.  For now, remove the final four characters.
			//
			// TODO(a.garipov): Either remove this crutch or support such
			// prefixes better.
			if len(s) == legacyHashPrefixEncLen {
				s = s[:HashPrefixEncLen]
			} else {
				return nil, fmt.Errorf("bad hash len for %q", s)
			}
		}

		prefixSet.Add(s)
	}

	hashPrefixes = make([]hashPrefix, prefixSet.Len())
	prefixStrs = prefixSet.Values()
	for i, s := range prefixStrs {
		_, err = hex.Decode(hashPrefixes[i][:], []byte(s))
		if err != nil {
			return nil, fmt.Errorf("bad hash encoding for %q", s)
		}
	}

	return hashPrefixes, nil
}

// type check
var _ agd.Refresher = (*HashStorage)(nil)

// Refresh implements the agd.Refresher interface for *HashStorage.  If the file
// at the storage's path exists and its mtime shows that it's still fresh, it
// loads the data from the file.  Otherwise, it uses the URL of the storage.
func (hs *HashStorage) Refresh(ctx context.Context) (err error) {
	err = hs.refresh(ctx, false)

	// Report the filter update to prometheus.
	promLabels := prometheus.Labels{
		"filter": string(hs.id()),
	}

	metrics.SetStatusGauge(metrics.FilterUpdatedStatus.With(promLabels), err)

	if err == nil {
		metrics.FilterUpdatedTime.With(promLabels).SetToCurrentTime()

		// Count the total number of hashes loaded.
		count := 0
		for _, v := range hs.hashSuffixes {
			count += len(v)
		}

		metrics.FilterRulesTotal.With(promLabels).Set(float64(count))
	}

	return err
}

// id returns the ID of the hash storage.
func (hs *HashStorage) id() (fltID agd.FilterListID) {
	return hs.refr.id
}

// refresh reloads the hash filter data.  If acceptStale is true, do not try to
// load the list from its URL when there is already a file in the cache
// directory, regardless of its staleness.
func (hs *HashStorage) refresh(ctx context.Context, acceptStale bool) (err error) {
	return hs.refr.refresh(ctx, acceptStale)
}

// resetHosts resets the hosts in the index.
func (hs *HashStorage) resetHosts(hostsStr string) (err error) {
	hs.mu.Lock()
	defer hs.mu.Unlock()

	// Delete all elements without allocating a new map to safe space and
	// performance.
	//
	// This is optimized, see https://github.com/golang/go/issues/20138.
	for hp := range hs.hashSuffixes {
		delete(hs.hashSuffixes, hp)
	}

	var n int
	s := bufio.NewScanner(strings.NewReader(hostsStr))
	for s.Scan() {
		host := s.Text()
		if len(host) == 0 || host[0] == '#' {
			continue
		}

		sum := sha256.Sum256([]byte(host))
		hp := hashPrefix{sum[0], sum[1]}

		// TODO(a.garipov): Convert to array directly when proposal
		// golang/go#46505 is implemented in Go 1.20.
		suf := *(*hashSuffix)(sum[hashPrefixLen:])
		hs.hashSuffixes[hp] = append(hs.hashSuffixes[hp], suf)

		n++
	}

	err = s.Err()
	if err != nil {
		return fmt.Errorf("scanning hosts: %w", err)
	}

	log.Info("filter %s: reset %d hosts", hs.id(), n)

	return nil
}

// Start implements the agd.Service interface for *HashStorage.
func (hs *HashStorage) Start() (err error) {
	return hs.refrWorker.Start()
}

// Shutdown implements the agd.Service interface for *HashStorage.
func (hs *HashStorage) Shutdown(ctx context.Context) (err error) {
	return hs.refrWorker.Shutdown(ctx)
}
