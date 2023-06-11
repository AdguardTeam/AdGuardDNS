package agdhttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/httphdr"
)

// Client is a wrapper around http.Client.
type Client struct {
	http      *http.Client
	userAgent string
}

// ClientConfig is the configuration structure for Client.
type ClientConfig struct {
	// Timeout is the timeout for all requests.
	Timeout time.Duration
}

// NewClient returns a new client.  c must not be nil.
func NewClient(conf *ClientConfig) (c *Client) {
	return &Client{
		http: &http.Client{
			Timeout: conf.Timeout,
		},
		userAgent: UserAgent(),
	}
}

// Get is a wrapper around http.Client.Get.
//
// When err is nil, resp always contains a non-nil resp.Body.  Caller should
// close resp.Body when done reading from it.
//
// See also go doc http.Client.Get.
func (c *Client) Get(ctx context.Context, u *url.URL) (resp *http.Response, err error) {
	return c.do(ctx, http.MethodGet, u, "", nil)
}

// Post is a wrapper around http.Client.Post.
//
// When err is nil, resp always contains a non-nil resp.Body.  Caller should
// close resp.Body when done reading from it.
//
// See also go doc http.Client.Post.
func (c *Client) Post(
	ctx context.Context,
	u *url.URL,
	contentType string,
	body io.Reader,
) (resp *http.Response, err error) {
	return c.do(ctx, http.MethodPost, u, contentType, body)
}

// Put is a wrapper around http.Client.Do.
//
// When err is nil, resp always contains a non-nil resp.Body.  Caller should
// close resp.Body when done reading from it.
func (c *Client) Put(
	ctx context.Context,
	u *url.URL,
	contentType string,
	body io.Reader,
) (resp *http.Response, err error) {
	return c.do(ctx, http.MethodPut, u, contentType, body)
}

// do is a wrapper around http.Client.Do.
func (c *Client) do(
	ctx context.Context,
	method string,
	u *url.URL,
	contentType string,
	body io.Reader,
) (resp *http.Response, err error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("creating %s request to: %w", method, err)
	}

	if contentType != "" {
		req.Header.Set(httphdr.ContentType, contentType)
	}

	reqID, ok := agd.RequestIDFromContext(ctx)
	if ok {
		req.Header.Set(httphdr.XRequestID, string(reqID))
	}

	req.Header.Set(httphdr.UserAgent, c.userAgent)

	resp, err = c.http.Do(req)
	if err != nil && resp != nil && resp.Header != nil {
		// A non-nil Response with a non-nil error only occurs when CheckRedirect fails.
		return resp, WrapServerError(err, resp)
	}

	return resp, err
}
