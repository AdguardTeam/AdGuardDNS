package websvc

import (
	"maps"
	"net/http"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
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

// type check
var _ http.Handler = StaticContent(nil)

// ServeHTTP implements the [http.Handler] interface for StaticContent.
func (sc StaticContent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	f, ok := sc[p]
	if !ok {
		http.NotFound(w, r)

		return
	}

	respHdr := w.Header()
	maps.Copy(respHdr, f.Headers)

	w.WriteHeader(http.StatusOK)
	_, err := w.Write(f.Content)
	if err != nil {
		ctx := r.Context()
		l := slogutil.MustLoggerFromContext(ctx)
		l.Log(ctx, levelForError(err), "writing static content", slogutil.KeyError, err)
	}
}
