package debugsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"path"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
)

// RefresherID is a type alias for strings that represent IDs of refreshers.
//
// TODO(a.garipov):  Consider a newtype with validations.
type RefresherID = string

// Refreshers is a type alias for maps of refresher IDs to Refreshers
// themselves.
type Refreshers map[RefresherID]service.Refresher

// refreshHandler performs debug refreshes.
type refreshHandler struct {
	refrs Refreshers
}

// refreshRequest describes the request to the POST /debug/api/refresh HTTP API.
//
// TODO(a.garipov):  Consider adding an "except" field.
type refreshRequest struct {
	// Patterns is the slice of path patterns to match the refreshers IDs.
	Patterns []string `json:"ids"`
}

// refreshResponse describes the response to the POST /debug/api/refresh HTTP
// API.
type refreshResponse struct {
	Results map[RefresherID]string `json:"results"`
}

// type check
var _ http.Handler = (*refreshHandler)(nil)

// ServeHTTP implements the [http.Handler] interface for *refreshHandler.
func (h *refreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := slogutil.MustLoggerFromContext(ctx)

	req := &refreshRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		l.ErrorContext(ctx, "decoding request", slogutil.KeyError, err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	reqIDs, err := h.idsFromReq(req.Patterns)
	if err != nil {
		l.ErrorContext(ctx, "validating request", slogutil.KeyError, err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	resp := &refreshResponse{
		Results: make(map[RefresherID]string, len(reqIDs)),
	}

	for _, id := range reqIDs {
		resp.Results[id] = h.refresh(ctx, l, id)
	}

	w.Header().Set(httphdr.ContentType, agdhttp.HdrValApplicationJSON)
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		l.ErrorContext(ctx, "writing response", slogutil.KeyError, err)
	}
}

// idsFromReq validates given patterns from the request and returns the IDs of
// matching refreshers to refresh.
//
// TODO(e.burkov): Validate patterns.
func (h *refreshHandler) idsFromReq(patterns []string) (ids []RefresherID, err error) {
	ok, err := isWildcard(patterns)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	refrIDs := slices.Collect(maps.Keys(h.refrs))
	if ok {
		return refrIDs, nil
	}

	return matchPatterns(refrIDs, patterns), nil
}

// refresh performs a single refresh and returns the result as a string.
func (h *refreshHandler) refresh(ctx context.Context, l *slog.Logger, id RefresherID) (res string) {
	r, ok := h.refrs[id]
	if !ok {
		return "error: refresher not found"
	}

	start := time.Now()
	err := r.Refresh(ctx)
	if err != nil {
		l.ErrorContext(ctx, "refresher error", "id", id, slogutil.KeyError, err)

		return fmt.Sprintf("error: %s", err)
	}

	l.InfoContext(ctx, "refresh finished", "id", id, "duration", time.Since(start))

	return "ok"
}

// isWildcard returns true if the list of patterns contains a single wildcard
// pattern.  It also returns an error if the list is empty or contains a
// wildcard pattern mixed with the others.
func isWildcard(patterns []string) (ok bool, err error) {
	switch len(patterns) {
	case 0:
		return false, errors.Error("no ids")
	case 1:
		if patterns[0] == "*" {
			return true, nil
		} else {
			return false, nil
		}
	default:
		if slices.Contains(patterns, "*") {
			return false, errors.Error(`"*" cannot be used with other ids`)
		} else {
			return false, nil
		}
	}
}

// matchPatterns matches ids against patterns and returns the resulting matches.
func matchPatterns(ids, patterns []string) (matches []string) {
	for _, pattern := range patterns {
		for _, id := range ids {
			if match, _ := path.Match(pattern, id); match {
				matches = append(matches, id)
			}
		}
	}

	return matches
}
