package websvc

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
)

// Config is the AdGuard DNS web service configuration structure.
type Config struct {
	// Logger is used for logging the operation of the web service.  It must not
	// be nil.
	Logger *slog.Logger

	// AdultBlocking is the optional adult-blocking block-page web server.
	AdultBlocking *BlockPageServerConfig

	// GeneralBlocking is the optional general block-page web server.
	GeneralBlocking *BlockPageServerConfig

	// SafeBrowsing is the optional safe-browsing block-page web server.
	SafeBrowsing *BlockPageServerConfig

	// LinkedIP is the optional linked IP web server.
	LinkedIP *LinkedIPServer

	// RootRedirectURL is the optional URL to which root HTTP requests are
	// redirected.  If not set, these requests are responded with a 404 page.
	RootRedirectURL *url.URL

	// CertificateValidator checks if an HTTP request is a TLS-certificate
	// validation request.  It must not be nil.
	CertificateValidator CertificateValidator

	// StaticContent is the content that is served statically at the given
	// paths.  It must not be nil; use [http.NotFoundHandler] if not needed.
	StaticContent http.Handler

	// DNSCheck is the HTTP handler for DNS checks.  It must not be nil.
	DNSCheck http.Handler

	// ErrColl is used to collect linked IP proxy errors and other errors.  It
	// must not be nil.
	ErrColl errcoll.Interface

	// Error404 is the optional content of the HTML page for the 404 status.  If
	// not set, a simple plain-text 404 response is served.
	Error404 []byte

	// Error500 is the optional content of the HTML page for the 500 status.  If
	// not set, a simple plain-text 500 response is served.
	Error500 []byte

	// NonDoHBind are the bind addresses and optional TLS configuration for the
	// web service in addition to the ones in the DNS-over-HTTPS handlers.  All
	// items must not be nil.
	NonDoHBind []*BindData

	// Timeout is the timeout for all server operations.  It must be positive.
	Timeout time.Duration
}

// BlockPageServerConfig is the blocking page server configuration.
type BlockPageServerConfig struct {
	// ContentFilePath is the path to HTML block page content file.  It must not
	// be empty.
	ContentFilePath string

	// Bind are the addresses on which to serve the block page.  At least one
	// must be provided.  All items must not be nil.
	Bind []*BindData
}

// BindData is data for binding one HTTP server to an address.
type BindData struct {
	// TLS is the optional TLS configuration.
	TLS *tls.Config

	// Address is the binding address.  It must not be empty.
	Address netip.AddrPort
}

// LinkedIPServer is the linked IP server configuration.
type LinkedIPServer struct {
	// TargetURL is the URL to which linked IP API requests are proxied.  It
	// must not be nil.
	TargetURL *url.URL

	// Bind are the addresses on which to serve the linked IP API.  At least one
	// must be provided.  All items must not be nil.
	Bind []*BindData
}

// CertificateValidator checks if an HTTP request is a TLS-certificate
// validation request.
type CertificateValidator interface {
	// IsValidWellKnownRequest returns true if r is a valid HTTP request for
	// certificate validation.  r must not be nil.
	IsValidWellKnownRequest(ctx context.Context, r *http.Request) (ok bool)
}

// RejectCertificateValidator is a [CertificateValidator] which rejects all HTTP
// requests.
type RejectCertificateValidator struct{}

// type check
var _ CertificateValidator = RejectCertificateValidator{}

// IsValidWellKnownRequest implements the [CertificateValidator] interface for
// RejectCertificateValidator.  It always returns false.
func (RejectCertificateValidator) IsValidWellKnownRequest(
	_ context.Context,
	_ *http.Request,
) (ok bool) {
	return false
}
