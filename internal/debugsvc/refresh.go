package debugsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"golang.org/x/exp/maps"
)

// RefresherID is a type alias for strings that represent IDs of refreshers.
//
// TODO(a.garipov):  Consider a newtype with validations.
type RefresherID = string

// Refreshers is a type alias for maps of refresher IDs to Refreshers
// themselves.
type Refreshers map[RefresherID]agdservice.Refresher

// refreshHandler performs debug refreshes.
type refreshHandler struct {
	refrs Refreshers
}

// refreshRequest describes the request to the POST /debug/api/refresh HTTP API.
type refreshRequest struct {
	IDs []RefresherID `json:"ids"`
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

	resp := &refreshResponse{
		Results: map[RefresherID]string{},
	}

	reqIDs, err := h.idsFromReq(req.IDs)
	if err != nil {
		l.ErrorContext(ctx, "validating request", slogutil.KeyError, err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	for _, id := range reqIDs {
		resp.Results[id] = h.refresh(ctx, l, id)
	}

	w.Header().Set(httphdr.ContentType, "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		l.ErrorContext(ctx, "writing response", slogutil.KeyError, err)
	}
}

// idsFromReq validates the form of the request and returns the IDs of
// refreshers to refresh.
func (h *refreshHandler) idsFromReq(reqIDs []RefresherID) (ids []RefresherID, err error) {
	l := len(reqIDs)
	switch l {
	case 0:
		return nil, errors.Error("no ids")
	case 1:
		if reqIDs[0] != "*" {
			return reqIDs, nil
		}

		allIDs := maps.Keys(h.refrs)
		slices.Sort(allIDs)

		return allIDs, nil
	default:
		starIdx := slices.Index(reqIDs, "*")
		if starIdx == -1 {
			return reqIDs, nil
		}

		return nil, errors.Error(`"*" cannot be used with other ids`)
	}
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
