package dnsdb

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"go.etcd.io/bbolt"
)

// BoltDB-Based DNSDB HTTP Handler

// type check
var _ http.Handler = (*Bolt)(nil)

// ServeHTTP implements the http.Handler interface for *Bolt.
func (db *Bolt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	db.dumpMu.Lock()
	defer db.dumpMu.Unlock()

	dbPath, err := db.flush(ctx, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	h := w.Header()
	h.Add(httphdr.ContentType, agdhttp.HdrValTextCSV)

	if dbPath == "" {
		// No data.
		w.WriteHeader(http.StatusOK)

		return
	}

	h.Set(httphdr.Trailer, httphdr.XError)
	defer func() {
		if err != nil {
			h.Set(httphdr.XError, err.Error())
			agd.Collectf(ctx, db.errColl, "dnsdb: http handler error: %w", err)
		}
	}()

	defer func() { err = errors.WithDeferred(err, os.Remove(dbPath)) }()

	var rw io.Writer = w
	// TODO(a.garipov): Consider parsing the quality value.
	if strings.Contains(r.Header.Get(httphdr.AcceptEncoding), "gzip") {
		h.Set(httphdr.ContentEncoding, "gzip")
		gw := gzip.NewWriter(w)
		defer func() { err = errors.WithDeferred(err, gw.Close()) }()

		rw = gw
	}

	w.WriteHeader(http.StatusOK)

	err = db.dumpToCSV(ctx, rw, dbPath)
}

// dumpToCSV converts the DNSDB at dbPath to CSV and writes it into w.  It
// writes every record as it processes it.
func (db *Bolt) dumpToCSV(ctx context.Context, w io.Writer, dbPath string) (err error) {
	bdb, err := openBolt(dbPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("opening boltdb: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, bdb.Close()) }()

	err = bdb.Batch(boltDumpFunc(ctx, w, db.errColl))
	if err != nil {
		return fmt.Errorf("dumping db: %w", err)
	}

	return nil
}

// boltDumpFunc returns a function that reads data from the existing DNSDB file
// and writes it into w as CSV records, one at a time.
//
// Decoding errors are reported using errColl.
func boltDumpFunc(ctx context.Context, w io.Writer, errColl agd.ErrorCollector) (f boltTxFunc) {
	return func(tx *bbolt.Tx) (err error) {
		b := tx.Bucket([]byte(recordsBucket))
		if b == nil {
			return errors.Error("records bucket not found")
		}

		csvw := csv.NewWriter(w)
		defer csvw.Flush()

		c := b.Cursor()
		for rk, v := c.First(); rk != nil; rk, v = c.Next() {
			var recs []*record
			err = gob.NewDecoder(bytes.NewReader(v)).Decode(&recs)
			if err != nil {
				agd.Collectf(ctx, errColl, "dnsdb: decoding data for %s: %w", rk, err)

				continue
			}

			err = writeCSVRecs(csvw, recs)
			if err != nil {
				return fmt.Errorf("writing record for key %s: %w", rk, err)
			}
		}

		return nil
	}
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
