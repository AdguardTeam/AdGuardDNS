package hashprefix

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Matcher is a hash-prefix matcher that uses the hash-prefix storages as the
// source of its data.
type Matcher struct {
	// storages is a mapping of domain-name suffixes to the storage containing
	// hashes for this domain.
	storages map[string]*Storage
}

// NewMatcher returns a new hash-prefix matcher.  storages is a mapping of
// domain-name suffixes to the storage containing hashes for this domain.
func NewMatcher(storages map[string]*Storage) (m *Matcher) {
	return &Matcher{
		storages: storages,
	}
}

// MatchByPrefix implements the [filter.HashMatcher] interface for *Matcher.  It
// returns the matched hashes if the host matched one of the domain names in m's
// storages.
//
// TODO(a.garipov): Use the context for logging etc.
func (m *Matcher) MatchByPrefix(
	_ context.Context,
	host string,
) (hashes []string, matched bool, err error) {
	var (
		suffix      string
		prefixesStr string
		strg        *Storage
	)

	for suffix, strg = range m.storages {
		if strings.HasSuffix(host, suffix) {
			prefixesStr = host[:len(host)-len(suffix)]
			matched = true

			break
		}
	}

	if !matched {
		return nil, false, nil
	}

	optlog.Debug1("hashprefix matcher: got prefixes string %q", prefixesStr)

	hashPrefixes, err := prefixesFromStr(prefixesStr)
	if err != nil {
		return nil, false, err
	}

	return strg.Hashes(hashPrefixes), true, nil
}

// legacyPrefixEncLen is the encoded length of a legacy hash.
const legacyPrefixEncLen = 8

// prefixesFromStr returns hash prefixes from a dot-separated string.
func prefixesFromStr(prefixesStr string) (hashPrefixes []Prefix, err error) {
	if prefixesStr == "" {
		return nil, nil
	}

	prefixSet := stringutil.NewSet()
	prefixStrs := strings.Split(prefixesStr, ".")
	for _, s := range prefixStrs {
		if len(s) != PrefixEncLen {
			// Some legacy clients send eight-character hashes instead of
			// four-character ones.  For now, remove the final four characters.
			//
			// TODO(a.garipov): Either remove this crutch or support such
			// prefixes better.
			if len(s) == legacyPrefixEncLen {
				s = s[:PrefixEncLen]
			} else {
				return nil, fmt.Errorf("bad hash len for %q", s)
			}
		}

		prefixSet.Add(s)
	}

	hashPrefixes = make([]Prefix, prefixSet.Len())
	prefixStrs = prefixSet.Values()
	for i, s := range prefixStrs {
		_, err = hex.Decode(hashPrefixes[i][:], []byte(s))
		if err != nil {
			return nil, fmt.Errorf("bad hash encoding for %q", s)
		}
	}

	return hashPrefixes, nil
}
