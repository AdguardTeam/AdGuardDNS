package cmd

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/websvc"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// Web Service Configuration

// webConfig contains configuration for the AdGuard DNS web service.
type webConfig struct {
	// LinkedIP is the optional linked IP web server.
	LinkedIP *linkedIPServer `yaml:"linked_ip"`

	// SafeBrowsing is the optional safe browsing block page web server.
	SafeBrowsing *blockPageServer `yaml:"safe_browsing"`

	// AdultBlocking is the optional adult blocking block page web server.
	AdultBlocking *blockPageServer `yaml:"adult_blocking"`

	// RootRedirectURL is the URL to which non-DNS and non-Debug HTTP requests
	// are redirected.  If not set, a 404 page is shown.
	RootRedirectURL *agdhttp.URL `yaml:"root_redirect_url"`

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

// toInternal converts c to the AdGuardDNS web service configuration.  c is
// assumed to be valid.
func (c *webConfig) toInternal(
	envs *environments,
	dnsCk http.Handler,
	errColl agd.ErrorCollector,
) (conf *websvc.Config, err error) {
	if c == nil {
		return nil, nil
	}

	conf = &websvc.Config{
		LinkedIPBackendURL: netutil.CloneURL(&envs.BackendEndpoint.URL),
		DNSCheck:           dnsCk,
		ErrColl:            errColl,
		Timeout:            c.Timeout.Duration,
	}

	if c.RootRedirectURL != nil {
		conf.RootRedirectURL = netutil.CloneURL(&c.RootRedirectURL.URL)
	}

	conf.LinkedIP, err = c.LinkedIP.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting linked_ip: %w", err)
	}

	conf.AdultBlocking, err = c.AdultBlocking.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting adult_blocking: %w", err)
	}

	conf.SafeBrowsing, err = c.SafeBrowsing.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting safe_browsing: %w", err)
	}

	conf.StaticContent, err = c.StaticContent.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting static_content: %w", err)
	}

	conf.Error404, conf.Error500, err = c.readErrorPages()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	conf.NonDoHBind, err = c.NonDoHBind.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting non_doh_bind: %w", err)
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

// validate returns an error if the web service configuration is invalid.
func (c *webConfig) validate() (err error) {
	switch {
	case c == nil:
		return nil
	case c.Timeout.Duration <= 0:
		return newMustBePositiveError("timeout", c.Timeout)
	default:
		// Go on.
	}

	err = c.LinkedIP.validate()
	if err != nil {
		return fmt.Errorf("linked_ip: %w", err)
	}

	err = c.SafeBrowsing.validate()
	if err != nil {
		return fmt.Errorf("safe_browsing: %w", err)
	}

	err = c.AdultBlocking.validate()
	if err != nil {
		return fmt.Errorf("adult_blocking: %w", err)
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

// toInternal converts s to a linkedIP server configuration.  s is assumed to be
// valid.
func (s *linkedIPServer) toInternal() (srv *websvc.LinkedIPServer, err error) {
	if s == nil {
		return nil, nil
	}

	srv = &websvc.LinkedIPServer{}
	srv.Bind, err = s.Bind.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting bind: %w", err)
	}

	return srv, nil
}

// validate returns an error if the linked IP server configuration is invalid.
func (s *linkedIPServer) validate() (err error) {
	switch {
	case s == nil:
		return nil
	case len(s.Bind) == 0:
		return errors.Error("no bind")
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
	// BlockPage is the content of the HTML block page.
	BlockPage string `yaml:"block_page"`

	// Bind are the bind addresses and optional TLS configuration for the block
	// page web servers.
	Bind bindData `yaml:"bind"`
}

// toInternal converts s to a block page server configuration.  s is assumed to
// be valid.
func (s *blockPageServer) toInternal() (srv *websvc.BlockPageServer, err error) {
	if s == nil {
		return nil, nil
	}

	srv = &websvc.BlockPageServer{}

	srv.Content, err = os.ReadFile(s.BlockPage)
	if err != nil {
		return nil, fmt.Errorf("reading block_page file: %w", err)
	}

	srv.Bind, err = s.Bind.toInternal()
	if err != nil {
		return nil, fmt.Errorf("converting bind: %w", err)
	}

	return srv, nil
}

// validate returns an error if the block page server configuration is invalid.
func (s *blockPageServer) validate() (err error) {
	switch {
	case s == nil:
		return nil
	case s.BlockPage == "":
		return errors.Error("no block_page")
	case len(s.Bind) == 0:
		return errors.Error("no bind")
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

// toInternal converts bd to bind data for the AdGuard DNS web service.  bd is
// assumed to be valid.
func (bd bindData) toInternal() (data []*websvc.BindData, err error) {
	data = make([]*websvc.BindData, len(bd))

	for i, d := range bd {
		data[i], err = d.toInternal()
		if err != nil {
			return nil, fmt.Errorf("bind data at index %d: %w", i, err)
		}
	}

	return data, nil
}

// validate returns an error if the bind data are invalid.
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

// toInternal converts i to bind data for the AdGuard DNS web service.  i is
// assumed to be valid.
func (i *bindItem) toInternal() (data *websvc.BindData, err error) {
	tlsConf, err := i.Certificates.toInternal()
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	return &websvc.BindData{
		TLS:     tlsConf,
		Address: i.Address,
	}, nil
}

// validate returns an error if the bind data are invalid.
func (i *bindItem) validate() (err error) {
	switch {
	case i == nil:
		return errors.Error("no bind data")
	case i.Address == netip.AddrPort{}:
		return errors.Error("no address")
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
// service.  sc is assumed to be valid.
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

// validate returns an error if the static content mapping is invalid.
func (sc staticContent) validate() (err error) {
	if len(sc) == 0 {
		return nil
	}

	// TODO(a.garipov): Sort the keys to make the order of validations
	// predictable.
	for p, f := range sc {
		if !path.IsAbs(p) {
			return fmt.Errorf("path %q: not absolute", p)
		}

		err = f.validate()
		if err != nil {
			return fmt.Errorf("path %q: %w", p, err)
		}
	}

	return nil
}

// staticFile is a single file in a static content mapping.
type staticFile struct {
	// ContentType is the value for the HTTP Content-Type header.
	ContentType string `yaml:"content_type"`

	// Content is the file content.
	Content string `yaml:"content"`
}

// toInternal converts f to a static file for the AdGuard DNS web service.  f is
// assumed to be valid.
func (f *staticFile) toInternal() (file *websvc.StaticFile, err error) {
	file = &websvc.StaticFile{
		ContentType: f.ContentType,
	}

	file.Content, err = base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, fmt.Errorf("content: %w", err)
	}

	return file, nil
}

// validate returns an error if the static content file is invalid.
func (f *staticFile) validate() (err error) {
	switch {
	case f == nil:
		return errors.Error("no file")
	case f.ContentType == "":
		return errors.Error("no content_type")
	default:
		return nil
	}
}
