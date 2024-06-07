package websvc

import (
	"maps"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
)

// StaticContent serves static content with the given content type.  Elements
// must not be nil.
type StaticContent map[string]*StaticFile

// StaticFile is a single file in a [StaticFS].
type StaticFile struct {
	// Headers contains headers of the HTTP response.
	Headers http.Header

	// Content is the file content.
	Content []byte
}

// serveHTTP serves the static content, if any.  If the mapping doesn't include
// the path from the request, served is false.
func (sc StaticContent) serveHTTP(w http.ResponseWriter, r *http.Request) (served bool) {
	p := r.URL.Path
	f, ok := sc[p]
	if !ok {
		return false
	}

	respHdr := w.Header()
	maps.Copy(respHdr, f.Headers)

	w.WriteHeader(http.StatusOK)

	_, err := w.Write(f.Content)
	if err != nil {
		logErrorByType(err, "websvc: static content: writing %s: %s", p, err)
	}

	metrics.WebSvcStaticContentRequestsTotal.Inc()

	return true
}
