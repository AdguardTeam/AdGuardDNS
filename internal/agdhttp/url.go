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
