package agdhttp

import (
	"fmt"
	"net/url"

	"github.com/AdguardTeam/golibs/errors"
)

// URL Types And Utilities

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
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, &url.Error{
			Op:  "parse",
			URL: s,
			Err: fmt.Errorf("bad scheme %q", u.Scheme),
		}
	default:
		return u, nil
	}
}

// URL is a wrapper around *url.URL that can unmarshal itself from JSON or YAML.
//
// TODO(a.garipov): Move to netutil if we need it somewhere else.
type URL struct {
	url.URL
}

// UnmarshalText implements the encoding.TextUnmarshaler interface for *URL.
func (u *URL) UnmarshalText(b []byte) (err error) {
	return u.UnmarshalBinary(b)
}
