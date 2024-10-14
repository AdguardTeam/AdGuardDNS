package agdhttp

import (
	"fmt"
	"net/url"

	"github.com/AdguardTeam/golibs/errors"
)

// Known scheme constants.
//
// TODO(a.garipov):  Move to agdurl or golibs.
//
// TODO(a.garipov):  Use more.
const (
	SchemeFile  = "file"
	SchemeGRPC  = "grpc"
	SchemeGRPCS = "grpcs"
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

// CheckGRPCURLScheme returns true if s is a valid gRPC URL scheme.  That is,
// [SchemeGRPC] or [SchemeGRPCS]
//
// TODO(a.garipov):  Move to golibs?
func CheckGRPCURLScheme(s string) (ok bool) {
	switch s {
	case SchemeGRPC, SchemeGRPCS:
		return true
	default:
		return false
	}
}

// CheckHTTPURLScheme returns true if s is a valid HTTP URL scheme.  That is,
// [SchemeHTTP] or [SchemeHTTPS]
//
// TODO(a.garipov):  Move to golibs?
func CheckHTTPURLScheme(s string) (ok bool) {
	switch s {
	case SchemeHTTP, SchemeHTTPS:
		return true
	default:
		return false
	}
}

// ParseHTTPURL parses an absolute URL and makes sure that it is a valid HTTP(S)
// URL.  All returned errors will have the underlying type [*url.Error].
//
// TODO(a.garipov): Define as a type?
func ParseHTTPURL(s string) (u *url.URL, err error) {
	u, err = url.Parse(s)
	if err != nil {
		return nil, err
	}

	switch {
	case u.Host == "":
		return nil, &url.Error{
			Op:  "parse",
			URL: s,
			Err: errors.Error("empty host"),
		}
	case !CheckHTTPURLScheme(u.Scheme):
		return nil, &url.Error{
			Op:  "parse",
			URL: s,
			Err: fmt.Errorf("bad scheme %q", u.Scheme),
		}
	default:
		return u, nil
	}
}
