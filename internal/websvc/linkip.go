package websvc

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
)

// linkedIPProxy proxies selected requests to a remote address.
type linkedIPProxy struct {
	httpProxy *httputil.ReverseProxy
	errColl   errcoll.Interface
}

// newLinkedIPHandler returns a linked IP proxy handler.  All arguments must be
// set.
func newLinkedIPHandler(
	apiURL *url.URL,
	errColl errcoll.Interface,
	proxyLogger *slog.Logger,
	timeout time.Duration,
) (h http.Handler) {
	// Use a Rewrite func to make sure we send the correct Host header and don't
	// send anything besides the path.
	rewrite := func(r *httputil.ProxyRequest) {
		r.SetURL(apiURL)
		r.Out.Host = apiURL.Host

		// Make sure that all requests are marked with our user agent.
		r.Out.Header.Set(httphdr.UserAgent, agdhttp.UserAgent())

		// Set the X-Forwarded-* headers for the backend to inspect cert
		// validation requests.
		r.SetXForwarded()
	}

	// Use largely the same transport as http.DefaultTransport, but with a
	// couple of limits and timeouts changed.
	//
	// TODO(ameshkov): Validate the configuration and consider making parts of
	// it configurable.
	//
	// TODO(e.burkov): Consider using the same transport for all the linked IP
	// handlers.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Delete the Server header value from the upstream.
	modifyResponse := func(r *http.Response) (err error) {
		r.Header.Del(httphdr.Server)

		// Make sure that this URL can be used from the web page.
		r.Header.Set(httphdr.AccessControlAllowOrigin, agdhttp.HdrValWildcard)

		return nil
	}

	// Collect errors using our own error collector.
	handlerWithError := func(_ http.ResponseWriter, r *http.Request, err error) {
		ctx := r.Context()
		reqID, _ := agd.RequestIDFromContext(ctx)

		l := slogutil.MustLoggerFromContext(ctx).With("req_id", reqID)
		errcoll.Collect(ctx, errColl, l, "proxying", err)
	}

	return &linkedIPProxy{
		httpProxy: &httputil.ReverseProxy{
			Rewrite:        rewrite,
			Transport:      transport,
			ErrorLog:       slog.NewLogLogger(proxyLogger.Handler(), slog.LevelDebug),
			ModifyResponse: modifyResponse,
			ErrorHandler:   handlerWithError,
		},
		errColl: errColl,
	}
}

// type check
var _ http.Handler = (*linkedIPProxy)(nil)

// ServeHTTP implements the http.Handler interface for *linkedIPProxy.
func (prx *linkedIPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set the Server header here, so that all 404 and 500 responses carry it.
	respHdr := w.Header()
	respHdr.Set(httphdr.Server, agdhttp.UserAgent())

	ctx := r.Context()
	l := slogutil.MustLoggerFromContext(ctx)

	if shouldProxy(r) {
		// TODO(a.garipov): Consider moving some or all this request
		// modification to the Director function if there are more handlers like
		// this in the future.

		// Remove all proxy headers before sending the request to proxy.
		hdr := r.Header
		hdr.Del(httphdr.CFConnectingIP)
		hdr.Del(httphdr.Forwarded)
		hdr.Del(httphdr.TrueClientIP)
		hdr.Del(httphdr.XRealIP)

		// Set the real IP.
		ip, err := netutil.SplitHost(r.RemoteAddr)
		if err != nil {
			err = fmt.Errorf("websvc: linked ip proxy: getting ip: %w", err)
			prx.errColl.Collect(ctx, err)

			// Send a 500 error, despite the fact that this is probably a client
			// error, because this is the code that the frontend expects.
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		hdr.Set(httphdr.XConnectingIP, ip)

		// Set the request ID.
		reqID := agd.NewRequestID()
		r = r.WithContext(agd.WithRequestID(r.Context(), reqID))
		hdr.Set(httphdr.XRequestID, reqID.String())

		l.DebugContext(ctx, "starting to proxy", "req_id", reqID)

		prx.httpProxy.ServeHTTP(w, r)

		metrics.WebSvcLinkedIPProxyRequestsTotal.Inc()
	} else if r.URL.Path == "/robots.txt" {
		serveRobotsDisallow(ctx, respHdr, w)
	} else {
		http.NotFound(w, r)
	}
}

// shouldProxy returns true if the request should be proxied.  Requests that
// should be proxied are the following:
//
//   - GET /linkip/{device_id}/{encrypted}
//   - GET /linkip/{device_id}/{encrypted}/status
//   - POST /ddns/{device_id}/{encrypted}/{domain}
//   - POST /linkip/{device_id}/{encrypted}
//
// As well as the well-known paths used for certificate validation.
//
// TODO(a.garipov):  Use mux routes.
func shouldProxy(r *http.Request) (ok bool) {
	// TODO(a.garipov):  Remove the /.well-known/ crutch once the data about the
	// actual URLs becomes available.
	if isWellKnown(r) {
		return true
	}

	method, urlPath := r.Method, r.URL.Path
	parts := strings.SplitN(strings.TrimPrefix(urlPath, "/"), "/", 5)
	if l := len(parts); l < 3 || l > 4 {
		return false
	}

	switch method {
	case http.MethodGet:
		return shouldProxyGet(parts)
	case http.MethodPost:
		return shouldProxyPost(parts)
	default:
		return false
	}
}

// shouldProxyGet returns true if the GET request should be proxied.  See
// shouldProxy for more info.
func shouldProxyGet(parts []string) (ok bool) {
	l := len(parts)

	return parts[0] == "linkip" &&
		(l == 3 || (l == 4 && parts[3] == "status"))
}

// shouldProxyPost returns true if the Post request should be proxied.  See
// shouldProxy for more info.
func shouldProxyPost(parts []string) (ok bool) {
	l := len(parts)
	firstPart := parts[0]

	return (firstPart == "ddns" && l == 4) ||
		(firstPart == "linkip" && l == 3)
}
