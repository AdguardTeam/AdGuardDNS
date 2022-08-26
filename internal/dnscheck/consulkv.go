package dnscheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/time/rate"
)

// Consul KV Database Client
//
// TODO(a.garipov): Consider replacing this with an actual consul client module.

// consulKV is the client for key-value database storing information about DNS
// requests.
type consulKV interface {
	// get returns a value by key from the database.
	get(ctx context.Context, key string) (inf *info, err error)

	// set sets inf into the database by key.
	set(ctx context.Context, key string, inf *info) (err error)
}

// nopKV is the key-value database client that does nothing.
type nopKV struct{}

// type check
var _ consulKV = nopKV{}

// get implements the consulKV interface for noopKV.
func (nopKV) get(_ context.Context, _ string) (inf *info, err error) {
	return nil, nil
}

// set implements the consulKV interface for noopKV.
func (nopKV) set(_ context.Context, _ string, _ *info) (err error) {
	return nil
}

// httpKV is the Consul KV database HTTP client.
type httpKV struct {
	url     *url.URL
	sessURL *url.URL
	http    *agdhttp.Client
	limiter *rate.Limiter
	ttl     time.Duration
}

// type check
var _ consulKV = &httpKV{}

// get implements the consulKV interface for *consulKV.
func (kv *httpKV) get(ctx context.Context, key string) (inf *info, err error) {
	err = kv.limiter.Wait(ctx)
	if err != nil {
		log.Error("dnscheck: request with id %q rate limited: %s", key, err)

		return nil, errRateLimited
	}

	u := kv.url.JoinPath(key)
	httpResp, err := kv.http.Get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("getting key %q from consul: %w", key, err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	var resp []*consulKVResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return nil, agdhttp.WrapServerError(
			fmt.Errorf("decoding response for key %q from consul: %w", key, err),
			httpResp,
		)
	}

	// Expect one item in response.
	if len(resp) == 0 || resp[0] == nil {
		return nil, agdhttp.WrapServerError(
			fmt.Errorf("response for key %q from consul has no items", key),
			httpResp,
		)
	}

	inf = &info{}
	err = json.Unmarshal(resp[0].Value, inf)
	if err != nil {
		return nil, agdhttp.WrapServerError(
			fmt.Errorf("decoding value for key %q from consul: %w", key, err),
			httpResp,
		)
	}

	return inf, nil
}

// consulKVResponse is the item of the array that Consul returns as a response
// to a GET request to its KV database.
type consulKVResponse struct {
	Value []byte `json:"Value"`
}

// consulSessionRequest is the session creation request.
//
// See https://www.consul.io/api-docs/session#create-session.
type consulSessionRequest struct {
	Name     string            `json:"Name"`
	Behavior string            `json:"Behavior"`
	TTL      timeutil.Duration `json:"TTL"`
}

// consulSessionResponse is the response to the session creation request.
//
// See https://www.consul.io/api-docs/session#create-session.
type consulSessionResponse struct {
	ID string `json:"ID"`
}

// consulSessionBehavior is the default Consul session behavior.  Use the
// "delete" behavior to emulate setting a TTL on a key.
//
// See https://www.consul.io/docs/dynamic-app-config/sessions#session-design.
const consulSessionBehavior = "delete"

// set implements the consulKV interface for *consulKV.
func (kv *httpKV) set(ctx context.Context, key string, inf *info) (err error) {
	sessURL := netutil.CloneURL(kv.sessURL)
	sessReq := &consulSessionRequest{
		Name:     fmt.Sprintf("ad_guard_dns_session_%d", time.Now().UnixNano()),
		Behavior: consulSessionBehavior,
		TTL:      timeutil.Duration{Duration: kv.ttl},
	}
	b, err := json.Marshal(sessReq)
	if err != nil {
		return fmt.Errorf("encoding session req for key %q for consul: %w", key, err)
	}

	var sessHTTPResp *http.Response
	sessHTTPResp, err = kv.http.Put(ctx, sessURL, agdhttp.HdrValApplicationJSON, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("getting session for key %q in consul: %w", key, err)
	}
	defer func() { err = errors.WithDeferred(err, sessHTTPResp.Body.Close()) }()

	sessResp := &consulSessionResponse{}
	err = json.NewDecoder(sessHTTPResp.Body).Decode(sessResp)
	if err != nil {
		return fmt.Errorf("decoding session id for key %q for consul: %w", key, err)
	}

	u := kv.url.JoinPath(key)
	v := &url.Values{
		"acquire": []string{sessResp.ID},
	}
	u.RawQuery = v.Encode()

	b, err = json.Marshal(inf)
	if err != nil {
		return fmt.Errorf("encoding value for key %q for consul: %w", key, err)
	}

	resp, err := kv.http.Put(ctx, u, "", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("setting key %q in consul: %w", key, err)
	}
	defer func() { err = errors.WithDeferred(err, resp.Body.Close()) }()

	return nil
}

// validateConsulURL returns an error if the Consul KV URL is invalid.
func validateConsulURL(u *url.URL) (err error) {
	if u == nil {
		return errors.Error("nil consul url")
	}

	defer func() { err = errors.Annotate(err, "consul url: path %q: %w", u.Path) }()

	parts := strings.Split(u.Path, "/")
	l := len(parts)
	if l < 2 {
		return errors.Error("too few parts")
	}

	if parts[l-2] != "kv" {
		return fmt.Errorf("next to last part is %q, want %q", parts[l-2], "kv")
	} else if parts[l-1] == "" {
		return errors.Error("last part is empty")
	}

	return nil
}
