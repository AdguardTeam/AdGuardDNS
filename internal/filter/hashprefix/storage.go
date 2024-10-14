package hashprefix

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Storage stores hashes of the filtered hostnames.  All methods are safe for
// concurrent use.
//
// TODO(a.garipov): See if we could unexport this.
type Storage struct {
	// resetMu makes sure that only one reset is taking place at a time.  It
	// also protects prev.
	resetMu *sync.Mutex

	// hashSuffixes contains the hashSuffixes map.  It is an atomic pointer to
	// make sure that calls to [Storage.Reset] do not block [Storage.Matches]
	// and thus filtering.
	hashSuffixes *atomic.Pointer[suffixMap]
}

// suffixMap is a convenient alias for a map of hash prefixes to its suffixes.
type suffixMap = map[Prefix][]suffix

// NewStorage returns a new hash storage containing hashes of the domain names
// listed in hostnames, one domain name per line, requirements are described in
// [Storage.Reset].  Empty string causes no errors.
func NewStorage(hostnames string) (s *Storage, err error) {
	s = &Storage{
		resetMu:      &sync.Mutex{},
		hashSuffixes: &atomic.Pointer[suffixMap]{},
	}

	s.hashSuffixes.Store(&suffixMap{})

	if hostnames != "" {
		_, err = s.Reset(hostnames)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Hashes returns all hashes starting with the given prefixes, if any.  The
// resulting slice shares storage for all underlying strings.
//
// TODO(a.garipov): This currently doesn't take duplicates into account.
func (s *Storage) Hashes(prefs []Prefix) (hashes []string) {
	if len(prefs) == 0 {
		return nil
	}

	// First, calculate the number of hashes to allocate the buffer.
	hashSuffixes := *s.hashSuffixes.Load()
	l := 0
	for _, pref := range prefs {
		hashSufs := hashSuffixes[pref]
		l += len(hashSufs)
	}

	// Then, allocate the buffer of the appropriate size and write all hashes
	// into one big buffer and slice it into separate strings to make the
	// garbage collector's work easier.  This assumes that all references to
	// this buffer will become unreachable at the same time.
	//
	// The fact that we iterate over the [s.hashSuffixes] map twice shouldn't
	// matter, since we assume that len(hps) will be below 5 most of the time.
	b := &strings.Builder{}
	b.Grow(l * hashEncLen)

	// Use a buffer and write the resulting buffer into b directly instead of
	// using hex.NewEncoder, because that seems to incur a significant
	// performance hit.
	var buf [hashEncLen]byte
	for _, pref := range prefs {
		hashSufs := hashSuffixes[pref]
		for _, suf := range hashSufs {
			hex.Encode(buf[:], pref[:])
			hex.Encode(buf[PrefixEncLen:], suf[:])
			_, _ = b.Write(buf[:])
		}
	}

	str := b.String()
	hashes = make([]string, 0, l)
	for i := range l {
		hashes = append(hashes, str[i*hashEncLen:(i+1)*hashEncLen])
	}

	return hashes
}

// Matches returns true if the host matches one of the hashes.
func (s *Storage) Matches(host string) (ok bool) {
	sum := sha256.Sum256([]byte(host))
	pref := Prefix(sum[:PrefixLen])

	var buf [hashLen]byte
	hashSufs, ok := s.loadHashSuffixes(pref)
	if !ok {
		return false
	}

	copy(buf[:], pref[:])
	for _, suf := range hashSufs {
		copy(buf[PrefixLen:], suf[:])
		if buf == sum {
			return true
		}
	}

	return false
}

// loadHashSuffixes returns hash suffixes for the given prefix.  It is safe for
// concurrent use.  sufs must not be modified.
func (s *Storage) loadHashSuffixes(pref Prefix) (sufs []suffix, ok bool) {
	suffixes := *s.hashSuffixes.Load()
	sufs, ok = suffixes[pref]

	return sufs, ok
}

// Reset resets the hosts in the index using the domain names listed in
// hostnames and returns the total number of processed rules.  hostnames should
// be a list of valid, lowercased domain names, one per line, and may include
// empty lines and comments ('#' at the first position).
func (s *Storage) Reset(hostnames string) (n int, err error) {
	s.resetMu.Lock()
	defer s.resetMu.Unlock()

	next := make(suffixMap, len(*s.hashSuffixes.Load()))

	sc := bufio.NewScanner(strings.NewReader(hostnames))
	for sc.Scan() {
		host := sc.Text()
		if len(host) == 0 || host[0] == '#' {
			continue
		}

		sum := sha256.Sum256([]byte(host))
		pref := Prefix(sum[:PrefixLen])
		suf := suffix(sum[PrefixLen:])
		next[pref] = append(next[pref], suf)

		n++
	}

	err = sc.Err()
	if err != nil {
		return 0, fmt.Errorf("scanning hosts: %w", err)
	}

	s.hashSuffixes.Store(&next)

	// Do not try to clear and reuse the previous map.  Any attempt to do that
	// in a thread-safe fashion will result in excessive locking and complexity.

	return n, nil
}
