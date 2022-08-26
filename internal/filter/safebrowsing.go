package filter

import (
	"context"
	"strings"

	"github.com/AdguardTeam/golibs/log"
)

// Safe Browsing TXT Record Server

// SafeBrowsingServer is a safe browsing server that responds to TXT DNS queries
// to known domains.
//
// TODO(a.garipov): Consider making an interface to simplify testing.
type SafeBrowsingServer struct {
	generalHashes       *HashStorage
	adultBlockingHashes *HashStorage
}

// NewSafeBrowsingServer returns a new safe browsing DNS server.
func NewSafeBrowsingServer(general, adultBlocking *HashStorage) (f *SafeBrowsingServer) {
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
	var strg *HashStorage

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

	return strg.hashes(hashPrefixes), true, nil
}
