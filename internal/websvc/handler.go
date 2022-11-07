package websvc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/sys/unix"
)

// HTTP Handlers

// type check
var _ http.Handler = (*Service)(nil)

// ServeHTTP implements the http.Handler interface for *Service.
func (svc *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respHdr := w.Header()
	respHdr.Set(agdhttp.HdrNameServer, agdhttp.UserAgent())

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
			respHdr.Set(agdhttp.HdrNameContentType, agdhttp.HdrValTextHTML)
		}
	case http.StatusInternalServerError:
		action = "writing 500"
		if len(svc.error500) != 0 {
			body = svc.error500
			respHdr.Set(agdhttp.HdrNameContentType, agdhttp.HdrValTextHTML)
		}
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
	case "/robots.txt":
		serveRobotsDisallow(w.Header(), w, "handler")
	case "/":
		if svc.rootRedirectURL == "" {
			http.NotFound(w, r)
		} else {
			http.Redirect(w, r, svc.rootRedirectURL, http.StatusFound)
		}
	default:
		http.NotFound(w, r)
	}
}

// safeBrowsingHandler returns an HTTP handler serving the block page from the
// blockPagePath.  name is used for logging.
func safeBrowsingHandler(name string, blockPage []byte) (h http.Handler) {
	f := func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set(agdhttp.HdrNameServer, agdhttp.UserAgent())

		switch r.URL.Path {
		case "/favicon.ico":
			// Don't serve the HTML page to the favicon requests.
			http.NotFound(w, r)
		case "/robots.txt":
			// Don't serve the HTML page to the robots.txt requests.  Serve
			// the predefined response instead.
			serveRobotsDisallow(hdr, w, name)
		default:
			hdr.Set(agdhttp.HdrNameContentType, agdhttp.HdrValTextHTML)

			_, err := w.Write(blockPage)
			if err != nil {
				logErrorByType(err, "websvc: %s: writing response: %s", name, err)
			}
		}
	}

	return http.HandlerFunc(f)
}

// StaticContent serves static content with the given content type.
type StaticContent map[string]*StaticFile

// serveHTTP serves the static content, if any.  If the mapping doesn't include
// the path from the request, served is false.
func (sc StaticContent) serveHTTP(w http.ResponseWriter, r *http.Request) (served bool) {
	p := r.URL.Path
	f, ok := sc[p]
	if !ok {
		return false
	}

	if f.AllowOrigin != "" {
		w.Header().Set(agdhttp.HdrNameAccessControlAllowOrigin, f.AllowOrigin)
	}
	w.Header().Set(agdhttp.HdrNameContentType, f.ContentType)
	w.WriteHeader(http.StatusOK)

	_, err := w.Write(f.Content)
	if err != nil {
		logErrorByType(err, "websvc: static content: writing %s: %s", p, err)
	}

	return true
}

// StaticFile is a single file in a StaticFS.
type StaticFile struct {
	// AllowOrigin is the value for the HTTP Access-Control-Allow-Origin header.
	AllowOrigin string

	// ContentType is the value for the HTTP Content-Type header.
	ContentType string

	// Content is the file content.
	Content []byte
}

// serveRobotsDisallow writes predefined disallow-all response.
func serveRobotsDisallow(hdr http.Header, w http.ResponseWriter, name string) {
	hdr.Set(agdhttp.HdrNameContentType, agdhttp.HdrValTextPlain)

	_, err := io.WriteString(w, agdhttp.RobotsDisallowAll)
	if err != nil {
		logErrorByType(err, "websvc: %s: writing response: %s", name, err)
	}
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
