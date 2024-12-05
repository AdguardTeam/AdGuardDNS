package dnsdb

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
)

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
			errcoll.Collect(ctx, db.errColl, db.logger, "handling http", err)
		}
	}()

	var rw io.Writer = w

	// TODO(a.garipov): Parse the quality value.
	//
	// TODO(a.garipov): Support other compression algorithms.
	if strings.Contains(r.Header.Get(httphdr.AcceptEncoding), agdhttp.HdrValGzip) {
		h.Set(httphdr.ContentEncoding, agdhttp.HdrValGzip)
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
