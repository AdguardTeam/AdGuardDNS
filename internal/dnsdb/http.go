package dnsdb

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
)

// Default DNS database HTTP Handler

// type check
var _ http.Handler = (*Default)(nil)

// ServeHTTP implements the http.Handler interface for *Default.
func (db *Default) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	ctx := r.Context()

	records := db.reset()

	h := w.Header()
	h.Add(httphdr.ContentType, agdhttp.HdrValTextCSV)

	h.Set(httphdr.Trailer, httphdr.XError)
	defer func() {
		if err != nil {
			h.Set(httphdr.XError, err.Error())
			agd.Collectf(ctx, db.errColl, "dnsdb: http handler error: %w", err)
		}
	}()

	var rw io.Writer = w
	// TODO(a.garipov): Consider parsing the quality value.
	if strings.Contains(r.Header.Get(httphdr.AcceptEncoding), "gzip") {
		h.Set(httphdr.ContentEncoding, "gzip")
		gw := gzip.NewWriter(w)
		defer func() { err = errors.WithDeferred(err, gw.Close()) }()

		rw = gw
	}

	w.WriteHeader(http.StatusOK)

	csvw := csv.NewWriter(rw)
	defer csvw.Flush()

	err = writeCSVRecs(csvw, records)
}

// writeCSVRecs writes the CSV representation of recs into w.
func writeCSVRecs(w *csv.Writer, recs []*record) (err error) {
	for i, r := range recs {
		err = w.Write(r.csv())
		if err != nil {
			return fmt.Errorf("record at index %d: %w", i, err)
		}
	}

	return nil
}
