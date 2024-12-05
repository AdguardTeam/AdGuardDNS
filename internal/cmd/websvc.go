package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/textproto"
	"os"
	"path"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// webConfig contains configuration for the AdGuard DNS web service.
type webConfig struct {
	// LinkedIP is the optional linked IP web server.
	LinkedIP *linkedIPServer `yaml:"linked_ip"`

	// AdultBlocking is the optional adult blocking block page web server.
	AdultBlocking *blockPageServer `yaml:"adult_blocking"`

	// GeneralBlocking is the optional general block-page web server.
	GeneralBlocking *blockPageServer `yaml:"general_blocking"`

	// SafeBrowsing is the optional safe browsing block page web server.
	SafeBrowsing *blockPageServer `yaml:"safe_browsing"`

	// RootRedirectURL is the URL to which non-DNS and non-Debug HTTP requests
	// are redirected.  If not set, a 404 page is shown.
	RootRedirectURL *urlutil.URL `yaml:"root_redirect_url"`

	// StaticContent is the content that is served statically at the given
	// paths.  If not set, no static content is shown.
	StaticContent staticContent `yaml:"static_content"`

	// Error404 is the path to the file with the HTML page for the 404 status.
	// If not set, a simple plain text 404 response is served.
	Error404 string `yaml:"error_404"`

	// Error500 is the path to the file with the HTML page for the 500 status.
	// If not set, a simple plain text 500 response is served.
	Error500 string `yaml:"error_500"`

	// NonDoHBind are the bind addresses and optional TLS configuration for the
	// web service in addition to the ones in the DNS-over-HTTPS handlers.
	NonDoHBind bindData `yaml:"non_doh_bind"`

	// Timeout is the timeout for all server operations.
	Timeout timeutil.Duration `yaml:"timeout"`
}

// toInternal converts c to the AdGuardDNS web service configuration.  c must be
// valid.
func (c *webConfig) toInternal(
	ctx context.Context,
	envs *environment,
	dnsCk dnscheck.Interface,
	errColl errcoll.Interface,
	tlsMgr tlsconfig.Manager,
) (conf *websvc.Config, err error) {
	if c == nil {
		return nil, nil
	}

	conf = &websvc.Config{
		ErrColl: errColl,
		Timeout: c.Timeout.Duration,
	}

	if dnsCkHdlr, ok := dnsCk.(http.Handler); ok {
		conf.DNSCheck = dnsCkHdlr
	}

	if c.RootRedirectURL != nil {
		conf.RootRedirectURL = netutil.CloneURL(&c.RootRedirectURL.URL)
	}

	conf.LinkedIP, err = c.LinkedIP.toInternal(ctx, tlsMgr, envs.LinkedIPTargetURL)
	if err != nil {
		return nil, fmt.Errorf("converting linked_ip: %w", err)
	}

	blockPages := []struct {
		webConfPtr **websvc.BlockPageServerConfig
		conf       *blockPageServer
		name       string
	}{{
		webConfPtr: &conf.AdultBlocking,
		conf:       c.AdultBlocking,
		name:       "adult_blocking",
	}, {
		webConfPtr: &conf.GeneralBlocking,
		conf:       c.GeneralBlocking,
		name:       "general_blocking",
	}, {
		webConfPtr: &conf.SafeBrowsing,
		conf:       c.SafeBrowsing,
		name:       "safe_browsing",
	}}

	for _, bp := range blockPages {
		*bp.webConfPtr, err = bp.conf.toInternal(ctx, tlsMgr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", bp.name, err)
		}
	}

	conf.Error404, conf.Error500, err = c.readErrorPages()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	conf.NonDoHBind, err = c.NonDoHBind.toInternal(ctx, tlsMgr)
	if err != nil {
		return nil, fmt.Errorf("converting non_doh_bind: %w", err)
	}

	err = c.setStaticContent(envs, conf)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return conf, nil
}

// readErrorPages returns the contents for the error pages in the configuration
// file and any errors encountered while reading them.
func (c *webConfig) readErrorPages() (error404, error500 []byte, err error) {
	if c.Error404 != "" {
		error404, err = os.ReadFile(c.Error404)
		if err != nil {
			return nil, nil, fmt.Errorf("reading error_404 file: %w", err)
		}
	}

	if c.Error500 != "" {
		error500, err = os.ReadFile(c.Error500)
		if err != nil {
			return nil, nil, fmt.Errorf("reading error_500 file: %w", err)
		}
	}

	return error404, error500, nil
}

// setStaticContent sets the static-content handler in conf using envs.
func (c *webConfig) setStaticContent(envs *environment, conf *websvc.Config) (err error) {
	if envs.WebStaticDirEnabled {
		conf.StaticContent = http.FileServer(http.Dir(envs.WebStaticDir))

		return nil
	}

	conf.StaticContent, err = c.StaticContent.toInternal()
	if err != nil {
		return fmt.Errorf("converting static_content: %w", err)
	}

	return nil
}

// type check
var _ validator = (*webConfig)(nil)

// validate implements the [validator] interface for *webConfig.
func (c *webConfig) validate() (err error) {
	switch {
	case c == nil:
		return nil
	case c.Timeout.Duration <= 0:
		return newNotPositiveError("timeout", c.Timeout)
	default:
		// Go on.
	}

	err = c.LinkedIP.validate()
	if err != nil {
		return fmt.Errorf("linked_ip: %w", err)
	}

	err = c.AdultBlocking.validate()
	if err != nil {
		return fmt.Errorf("adult_blocking: %w", err)
	}

	err = c.GeneralBlocking.validate()
	if err != nil {
		return fmt.Errorf("general_blocking: %w", err)
	}

	err = c.SafeBrowsing.validate()
	if err != nil {
		return fmt.Errorf("safe_browsing: %w", err)
	}

	err = c.StaticContent.validate()
	if err != nil {
		return fmt.Errorf("static_content: %w", err)
	}

	err = c.NonDoHBind.validate()
	if err != nil {
		return fmt.Errorf("non_doh_bind: %w", err)
	}

	return nil
}

// linkedIPServer is the linked IP web server configuration.
type linkedIPServer struct {
	// Bind are the bind addresses and optional TLS configuration for the linked
	// IP web servers.
	Bind bindData `yaml:"bind"`
}

// toInternal converts s to a linkedIP server configuration.  s must be valid.
func (s *linkedIPServer) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
	targetURL *urlutil.URL,
) (srv *websvc.LinkedIPServer, err error) {
	if s == nil {
		return nil, nil
	}

	srv = &websvc.LinkedIPServer{}
	srv.Bind, err = s.Bind.toInternal(ctx, tlsMgr)
	if err != nil {
		return nil, fmt.Errorf("converting bind: %w", err)
	}

	if targetURL == nil {
		return nil, fmt.Errorf("env variable LINKED_IP_TARGET_URL must be set for using linked_ip")
	}

	srv.TargetURL = netutil.CloneURL(&targetURL.URL)

	return srv, nil
}

// type check
var _ validator = (*linkedIPServer)(nil)

// validate implements the [validator] interface for *linkedIPServer.
func (s *linkedIPServer) validate() (err error) {
	switch {
	case s == nil:
		return nil
	case len(s.Bind) == 0:
		return fmt.Errorf("bind: %w", errors.ErrEmptyValue)
	default:
		// Go on.
	}

	err = s.Bind.validate()
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	return nil
}

// blockPageServer is the safe browsing or adult blocking block page web servers
// configuration.
type blockPageServer struct {
	// BlockPage is the path to file with HTML block page content.
	BlockPage string `yaml:"block_page"`

	// Bind are the bind addresses and optional TLS configuration for the block
	// page web servers.
	Bind bindData `yaml:"bind"`
}

// toInternal converts s to a block page server configuration.  s must be valid.
func (s *blockPageServer) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
) (conf *websvc.BlockPageServerConfig, err error) {
	if s == nil {
		return nil, nil
	}

	conf = &websvc.BlockPageServerConfig{
		ContentFilePath: s.BlockPage,
	}

	conf.Bind, err = s.Bind.toInternal(ctx, tlsMgr)
	if err != nil {
		return nil, fmt.Errorf("converting bind: %w", err)
	}

	return conf, nil
}

// type check
var _ validator = (*blockPageServer)(nil)

// validate implements the [validator] interface for *blockPageServer.
func (s *blockPageServer) validate() (err error) {
	switch {
	case s == nil:
		return nil
	case s.BlockPage == "":
		return fmt.Errorf("block_page: %w", errors.ErrEmptyValue)
	case len(s.Bind) == 0:
		return fmt.Errorf("bind: %w", errors.ErrEmptyValue)
	default:
		// Go on.
	}

	err = s.Bind.validate()
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	return nil
}

// bindData are the data for binding HTTP servers to addresses.
type bindData []*bindItem

// toInternal converts bd to bind data for the AdGuard DNS web service.  bd must
// be valid.
func (bd bindData) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
) (data []*websvc.BindData, err error) {
	data = make([]*websvc.BindData, len(bd))

	for i, d := range bd {
		data[i], err = d.toInternal(ctx, tlsMgr)
		if err != nil {
			return nil, fmt.Errorf("bind data at index %d: %w", i, err)
		}
	}

	return data, nil
}

// type check
var _ validator = bindData(nil)

// validate implements the [validator] interface for bindData.
func (bd bindData) validate() (err error) {
	if len(bd) == 0 {
		return nil
	}

	for i, d := range bd {
		err = d.validate()
		if err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}
	}

	return nil
}

// bindItem is data for binding one HTTP server to an address.
type bindItem struct {
	// Address is the binding address.
	Address netip.AddrPort `yaml:"address"`

	// Certificates are the optional TLS certificates for this HTTP(S) server.
	Certificates tlsConfigCerts `yaml:"certificates"`
}

// toInternal converts i to bind data for the AdGuard DNS web service.  i must
// be valid.
func (i *bindItem) toInternal(
	ctx context.Context,
	tlsMgr tlsconfig.Manager,
) (data *websvc.BindData, err error) {
	tlsConf, err := i.Certificates.toInternal(ctx, tlsMgr)
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	return &websvc.BindData{
		TLS:     tlsConf,
		Address: i.Address,
	}, nil
}

// type check
var _ validator = (*bindItem)(nil)

// validate implements the [validator] interface for *bindItem.
func (i *bindItem) validate() (err error) {
	switch {
	case i == nil:
		return errors.ErrNoValue
	case i.Address == netip.AddrPort{}:
		return fmt.Errorf("address: %w", errors.ErrEmptyValue)
	default:
		// Go on.
	}

	err = i.Certificates.validate()
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}

	return nil
}

// staticContent is the static content mapping.  Paths must be absolute and
// non-empty.
type staticContent map[string]*staticFile

// toInternal converts sc to a static content mapping for the AdGuard DNS web
// service.  sc must be valid.
func (sc staticContent) toInternal() (fs websvc.StaticContent, err error) {
	if len(sc) == 0 {
		return nil, nil
	}

	fs = make(websvc.StaticContent, len(sc))
	for p, f := range sc {
		fs[p], err = f.toInternal()
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", p, err)
		}
	}

	return fs, nil
}

// type check
var _ validator = staticContent(nil)

// validate implements the [validator] interface for staticContent.
func (sc staticContent) validate() (err error) {
	if len(sc) == 0 {
		return nil
	}

	for _, p := range slices.Sorted(maps.Keys(sc)) {
		if !path.IsAbs(p) {
			return fmt.Errorf("path %q: not absolute", p)
		}

		err = sc[p].validate()
		if err != nil {
			return fmt.Errorf("path %q: %w", p, err)
		}
	}

	return nil
}

// staticFile is a single file in a static content mapping.
type staticFile struct {
	// Headers contains headers of the HTTP response.
	Headers http.Header `yaml:"headers"`

	// Content is the file content.
	Content string `yaml:"content"`
}

// toInternal converts f to a static file for the AdGuard DNS web service.  f
// must be valid.
func (f *staticFile) toInternal() (file *websvc.StaticFile, err error) {
	file = &websvc.StaticFile{
		Headers: http.Header{},
	}

	for k, vs := range f.Headers {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		file.Headers[ck] = vs
	}

	file.Content, err = base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, fmt.Errorf("content: %w", err)
	}

	// Check Content-Type here as opposed to in validate, because we need
	// all keys to be canonicalized first.
	if file.Headers.Get(httphdr.ContentType) == "" {
		return nil, errors.Error("content: " + httphdr.ContentType + " header is required")
	}

	return file, nil
}

// type check
var _ validator = (*staticFile)(nil)

// validate implements the [validator] interface for *staticFile.
func (f *staticFile) validate() (err error) {
	if f == nil {
		return errors.ErrNoValue
	}

	return nil
}
