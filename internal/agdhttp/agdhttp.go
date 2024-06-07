// Package agdhttp contains common constants, functions, and types for working
// with HTTP.
//
// TODO(a.garipov): Consider moving all or some of this stuff to module golibs.
package agdhttp

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Common Constants, Functions And Types

// HTTP header value constants.
const (
	HdrValApplicationJSON = "application/json"
	HdrValGzip            = "gzip"
	HdrValTextCSV         = "text/csv"
	HdrValTextHTML        = "text/html"
	HdrValTextPlain       = "text/plain"
	HdrValWildcard        = "*"
)

// RobotsDisallowAll is a predefined robots disallow all content.
const RobotsDisallowAll = "User-agent: *\nDisallow: /\n"

// UserAgent returns the ID of the service as a User-Agent string.  It can also
// be used as the value of the Server HTTP header.
func UserAgent() (ua string) {
	return fmt.Sprintf("AdGuardDNS/%s", agd.Version())
}
