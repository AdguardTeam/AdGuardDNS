// Package agdhttp contains common constants, functions, and types for working
// with HTTP.
//
// TODO(a.garipov): Consider moving all or some of this stuff to module golibs.
package agdhttp

import "github.com/AdguardTeam/AdGuardDNS/internal/version"

// Common Constants, Functions And Types

// HTTP header value constants.
const (
	HdrValApplicationJSON        = "application/json"
	HdrValApplicationOctetStream = "application/octet-stream"
	HdrValGzip                   = "gzip"
	HdrValTextCSV                = "text/csv"
	HdrValTextHTML               = "text/html"
	HdrValTextPlain              = "text/plain"
	HdrValWildcard               = "*"
)

// RobotsDisallowAll is a predefined robots disallow all content.
const RobotsDisallowAll = "User-agent: *\nDisallow: /\n"

// userAgent is the cached User-Agent string for AdGuardDNS.
var userAgent = version.Name() + "/" + version.Version()

// UserAgent returns the ID of the service as a User-Agent string.  It can also
// be used as the value of the Server HTTP header.
func UserAgent() (ua string) {
	return userAgent
}
