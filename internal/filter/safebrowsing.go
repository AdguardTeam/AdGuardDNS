package filter

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashstorage"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Safe Browsing TXT Record Server

// SafeBrowsingServer is a safe browsing server that responds to TXT DNS queries
// to known domains.
//
// TODO(a.garipov): Consider making an interface to simplify testing.
type SafeBrowsingServer struct {
	generalHashes       *hashstorage.Storage
	adultBlockingHashes *hashstorage.Storage
}

// NewSafeBrowsingServer returns a new safe browsing DNS server.
func NewSafeBrowsingServer(general, adultBlocking *hashstorage.Storage) (f *SafeBrowsingServer) {
	return &SafeBrowsingServer{
		generalHashes:       general,
		adultBlockingHashes: adultBlocking,
	}
}

// Default safe browsing host suffixes.
//
// TODO(ameshkov): Consider making these configurable.
const (
	GeneralTXTSuffix       = ".sb.dns.adguard.com"
	AdultBlockingTXTSuffix = ".pc.dns.adguard.com"
)

// Hashes returns the matched hashes if the host matched one of the domain names
// in srv.
//
// TODO(a.garipov): Use the context for logging etc.
func (srv *SafeBrowsingServer) Hashes(
	_ context.Context,
	host string,
) (hashes []string, matched bool, err error) {
	// TODO(a.garipov): Remove this if SafeBrowsingServer becomes an interface.
	if srv == nil {
		return nil, false, nil
	}

	var prefixesStr string
	var strg *hashstorage.Storage
	if strings.HasSuffix(host, GeneralTXTSuffix) {
		prefixesStr = host[:len(host)-len(GeneralTXTSuffix)]
		strg = srv.generalHashes
	} else if strings.HasSuffix(host, AdultBlockingTXTSuffix) {
		prefixesStr = host[:len(host)-len(AdultBlockingTXTSuffix)]
		strg = srv.adultBlockingHashes
	} else {
		return nil, false, nil
	}

	log.Debug("safe browsing txt srv: got prefixes string %q", prefixesStr)

	hashPrefixes, err := hashPrefixesFromStr(prefixesStr)
	if err != nil {
		return nil, false, err
	}

	return strg.Hashes(hashPrefixes), true, nil
}

// legacyPrefixEncLen is the encoded length of a legacy hash.
const legacyPrefixEncLen = 8

// hashPrefixesFromStr returns hash prefixes from a dot-separated string.
func hashPrefixesFromStr(prefixesStr string) (hashPrefixes []hashstorage.Prefix, err error) {
	if prefixesStr == "" {
		return nil, nil
	}

	prefixSet := stringutil.NewSet()
	prefixStrs := strings.Split(prefixesStr, ".")
	for _, s := range prefixStrs {
		if len(s) != hashstorage.PrefixEncLen {
			// Some legacy clients send eight-character hashes instead of
			// four-character ones.  For now, remove the final four characters.
			//
			// TODO(a.garipov): Either remove this crutch or support such
			// prefixes better.
			if len(s) == legacyPrefixEncLen {
				s = s[:hashstorage.PrefixEncLen]
			} else {
				return nil, fmt.Errorf("bad hash len for %q", s)
			}
		}

		prefixSet.Add(s)
	}

	hashPrefixes = make([]hashstorage.Prefix, prefixSet.Len())
	prefixStrs = prefixSet.Values()
	for i, s := range prefixStrs {
		_, err = hex.Decode(hashPrefixes[i][:], []byte(s))
		if err != nil {
			return nil, fmt.Errorf("bad hash encoding for %q", s)
		}
	}

	return hashPrefixes, nil
}
