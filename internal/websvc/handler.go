package websvc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/sys/unix"
)

// HTTP Handlers

// type check
var _ http.Handler = (*Service)(nil)

// ServeHTTP implements the http.Handler interface for *Service.
func (svc *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respHdr := w.Header()
	respHdr.Set(httphdr.Server, agdhttp.UserAgent())

	m, p, rAddr := r.Method, r.URL.Path, r.RemoteAddr
	optlog.Debug3("websvc: starting req %s %s from %s", m, p, rAddr)
	defer optlog.Debug3("websvc: finished req %s %s from %s", m, p, rAddr)

	if svc == nil {
		http.NotFound(w, r)

		return
	}

	rec := httptest.NewRecorder()
	svc.serveHTTP(rec, r)

	action, body := svc.processRec(respHdr, rec)
	w.WriteHeader(rec.Code)
	_, err := w.Write(body)
	if err != nil {
		logErrorByType(err, "websvc: handler: %s: %s", action, err)
	}
}

// processRec processes the response code in rec and returns the appropriate
// body and a description of the action for logging.  It also sets the necessary
// headers in respHdr.
func (svc *Service) processRec(
	respHdr http.Header,
	rec *httptest.ResponseRecorder,
) (action string, body []byte) {
	switch rec.Code {
	case http.StatusNotFound:
		action = "writing 404"
		if len(svc.error404) != 0 {
			body = svc.error404
			respHdr.Set(httphdr.ContentType, agdhttp.HdrValTextHTML)
		}

		metrics.WebSvcError404RequestsTotal.Inc()
	case http.StatusInternalServerError:
		action = "writing 500"
		if len(svc.error500) != 0 {
			body = svc.error500
			respHdr.Set(httphdr.ContentType, agdhttp.HdrValTextHTML)
		}

		metrics.WebSvcError500RequestsTotal.Inc()
	default:
		action = "writing response"
		for k, v := range rec.Header() {
			respHdr[k] = v
		}
	}

	if body == nil {
		body = rec.Body.Bytes()
	}

	return action, body
}

// serveHTTP processes the HTTP request.
func (svc *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if svc.staticContent.serveHTTP(w, r) {
		return
	}

	switch r.URL.Path {
	case "/dnscheck/test":
		svc.dnsCheck.ServeHTTP(w, r)

		metrics.WebSvcDNSCheckTestRequestsTotal.Inc()
	case "/robots.txt":
		serveRobotsDisallow(w.Header(), w, "handler")
	case "/":
		if svc.rootRedirectURL == "" {
			http.NotFound(w, r)
		} else {
			http.Redirect(w, r, svc.rootRedirectURL, http.StatusFound)

			metrics.WebSvcRootRedirectRequestsTotal.Inc()
		}
	default:
		http.NotFound(w, r)
	}
}

// serveRobotsDisallow writes predefined disallow-all response.
func serveRobotsDisallow(hdr http.Header, w http.ResponseWriter, name string) {
	hdr.Set(httphdr.ContentType, agdhttp.HdrValTextPlain)

	_, err := io.WriteString(w, agdhttp.RobotsDisallowAll)
	if err != nil {
		logErrorByType(err, "websvc: %s: writing response: %s", name, err)
	}

	metrics.WebSvcRobotsTxtRequestsTotal.Inc()
}

// logErrorByType writes err to the error log, unless err is a network error or
// a timeout error, in which case it is written to the debug log.
func logErrorByType(err error, format string, args ...any) {
	// TODO(d.kolyshev): Consider adding more error types.
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, unix.EPIPE) ||
		errors.Is(err, unix.ECONNRESET) {
		log.Debug(format, args...)
	} else {
		log.Error(format, args...)
	}
}
