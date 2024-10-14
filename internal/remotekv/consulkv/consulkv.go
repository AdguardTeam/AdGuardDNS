// Package consulkv contains implementation of [remotekv.Interface] for Consul
// key-value storage.
package consulkv

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
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/ioutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/c2h5oh/datasize"
	"golang.org/x/time/rate"
)

// Consul-related constants.
//
// See https://developer.hashicorp.com/consul/api-docs/session#ttl.
const (
	// MaxTTL is the maximum TTL that can be set for a session.
	MaxTTL = 1 * timeutil.Day

	// MinTTL is the minimum TTL that can be set for a session.
	MinTTL = 10 * time.Second
)

// Config is the configuration structure for Consul key-value storage.  All
// fields must be non-empty.
type Config struct {
	// URL to the Consul key-value storage.
	URL *url.URL

	// SessionURL is the URL to the Consul session API.
	SessionURL *url.URL

	// Client is the HTTP client for requests to the Consul key-value storage.
	Client *agdhttp.Client

	// Limiter rate limits requests to the Consul key-value storage.
	Limiter *rate.Limiter

	// TTL defines for how long information about a single client is kept.  It
	// must be between [MinTTL] and [MaxTTL].
	TTL time.Duration

	// MaxRespSize is the maximum size of response from Consul key-value
	// storage.
	MaxRespSize datasize.ByteSize
}

// KV is the Consul remote KV implementation.
type KV struct {
	url         *url.URL
	sessionURL  *url.URL
	client      *agdhttp.Client
	limiter     *rate.Limiter
	ttl         time.Duration
	maxRespSize datasize.ByteSize
}

// NewKV returns a new Consul key-value storage.
func NewKV(conf *Config) (kv *KV, err error) {
	// TODO(e.burkov):  Validate also c.ConsulSessionURL?
	err = validateConsulURL(conf.URL)
	if err != nil {
		return nil, err
	}

	return &KV{
		url:         conf.URL,
		sessionURL:  conf.SessionURL,
		client:      conf.Client,
		limiter:     conf.Limiter,
		ttl:         conf.TTL,
		maxRespSize: conf.MaxRespSize,
	}, nil
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

// type check
var _ remotekv.Interface = &KV{}

// Get implements the [remotekv.Interface] interface for *KV.  Any error
// returned will have the underlying type of [httpError].
func (kv *KV) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	defer func() {
		if err != nil {
			err = httpError{err: err}
		}
	}()

	err = kv.limiter.Wait(ctx)
	if err != nil {
		return nil, false, ErrRateLimited
	}

	u := kv.url.JoinPath(key)
	httpResp, err := kv.client.Get(ctx, u)
	if err != nil {
		return nil, false, fmt.Errorf("getting key %q from consul: %w", key, err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	// Note that, if no key exists at the given path, a 404 is returned instead
	// of a normal 200 response.
	//
	// See https://developer.hashicorp.com/consul/api-docs/kv#read-key.
	if httpResp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		return nil, false, fmt.Errorf("response for key %q: %w", key, err)
	}

	limitReader := ioutil.LimitReader(httpResp.Body, kv.maxRespSize.Bytes())

	var resp []*KeyReadResponse
	err = json.NewDecoder(limitReader).Decode(&resp)
	if err != nil {
		return nil, false, fmt.Errorf("decoding response for key %q from consul: %w", key, err)
	}

	// Expect one item in response.
	if len(resp) == 0 || resp[0] == nil {
		return nil, false, fmt.Errorf("response for key %q from consul has no items", key)
	}

	return resp[0].Value, true, nil
}

// KeyReadResponse is the item of the array that Consul returns as a response to
// a GET request to its KV database.
//
// See https://developer.hashicorp.com/consul/api-docs/kv#read-key.
type KeyReadResponse struct {
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

// Set implements the [remotekv.Interface] interface for *KV.  Any error
// returned will have the underlying type of [httpError].
func (kv *KV) Set(ctx context.Context, key string, val []byte) (err error) {
	defer func() {
		if err != nil {
			err = httpError{err: err}
		}
	}()

	sessReq := &consulSessionRequest{
		Name:     fmt.Sprintf("ad_guard_dns_session_%d", time.Now().UnixNano()),
		Behavior: consulSessionBehavior,
		TTL:      timeutil.Duration{Duration: kv.ttl},
	}
	b, err := json.Marshal(sessReq)
	if err != nil {
		return fmt.Errorf("encoding session req for key %q for consul: %w", key, err)
	}

	sessHTTPResp, err := kv.client.Put(
		ctx,
		kv.sessionURL,
		agdhttp.HdrValApplicationJSON,
		bytes.NewReader(b),
	)
	if err != nil {
		return fmt.Errorf("getting session for key %q in consul: %w", key, err)
	}
	defer func() { err = errors.WithDeferred(err, sessHTTPResp.Body.Close()) }()

	// Status 200 is expected.
	//
	// See https://developer.hashicorp.com/consul/api-docs/session.
	err = agdhttp.CheckStatus(sessHTTPResp, http.StatusOK)
	if err != nil {
		return fmt.Errorf("getting session for key %q: %w", key, err)
	}

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

	resp, err := kv.client.Put(ctx, u, "", bytes.NewReader(val))
	if err != nil {
		return fmt.Errorf("setting key %q in consul: %w", key, err)
	}
	defer func() { err = errors.WithDeferred(err, resp.Body.Close()) }()

	// Status 200 is expected.
	//
	// See https://github.com/hashicorp/consul/blob/main/api/kv.go#L224.
	err = agdhttp.CheckStatus(resp, http.StatusOK)
	if err != nil {
		return fmt.Errorf("setting key %q: %w", key, err)
	}

	return nil
}
