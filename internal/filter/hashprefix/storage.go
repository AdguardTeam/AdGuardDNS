package hashprefix

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// Storage stores hashes of the filtered hostnames.  All methods are safe for
// concurrent use.
//
// TODO(a.garipov): See if we could unexport this.
type Storage struct {
	// mu protects hashSuffixes.
	mu           *sync.RWMutex
	hashSuffixes map[Prefix][]suffix
}

// NewStorage returns a new hash storage containing hashes of the domain names
// listed in hostnames, one domain name per line.
func NewStorage(hostnames string) (s *Storage, err error) {
	s = &Storage{
		mu:           &sync.RWMutex{},
		hashSuffixes: map[Prefix][]suffix{},
	}

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

	s.mu.RLock()
	defer s.mu.RUnlock()

	// First, calculate the number of hashes to allocate the buffer.
	l := 0
	for _, pref := range prefs {
		hashSufs := s.hashSuffixes[pref]
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
		hashSufs := s.hashSuffixes[pref]
		for _, suf := range hashSufs {
			// nolint:looppointer // Slicing is safe; used for encoding.
			hex.Encode(buf[:], pref[:])
			// nolint:looppointer // Slicing is safe; used for encoding.
			hex.Encode(buf[PrefixEncLen:], suf[:])
			_, _ = b.Write(buf[:])
		}
	}

	str := b.String()
	hashes = make([]string, 0, l)
	for i := 0; i < l; i++ {
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
		// nolint:looppointer // Slicing is safe; used for copying.
		copy(buf[PrefixLen:], suf[:])
		if buf == sum {
			return true
		}
	}

	return false
}

// Reset resets the hosts in the index using the domain names listed in
// hostnames, one domain name per line, and returns the total number of
// processed rules.
func (s *Storage) Reset(hostnames string) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Delete all elements without allocating a new map to save space and
	// improve performance.
	//
	// This is optimized, see https://github.com/golang/go/issues/20138.
	//
	// TODO(a.garipov): Use clear once golang/go#56351 is implemented.
	for pref := range s.hashSuffixes {
		delete(s.hashSuffixes, pref)
	}

	sc := bufio.NewScanner(strings.NewReader(hostnames))
	for sc.Scan() {
		host := sc.Text()
		if len(host) == 0 || host[0] == '#' {
			continue
		}

		sum := sha256.Sum256([]byte(host))
		pref := Prefix(sum[:PrefixLen])
		suf := suffix(sum[PrefixLen:])
		s.hashSuffixes[pref] = append(s.hashSuffixes[pref], suf)

		n++
	}

	err = sc.Err()
	if err != nil {
		return 0, fmt.Errorf("scanning hosts: %w", err)
	}

	return n, nil
}

// loadHashSuffixes returns hash suffixes for the given prefix.  It is safe for
// concurrent use.  sufs must not be modified.
func (s *Storage) loadHashSuffixes(pref Prefix) (sufs []suffix, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sufs, ok = s.hashSuffixes[pref]

	return sufs, ok
}
