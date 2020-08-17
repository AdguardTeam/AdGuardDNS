package dnsdb

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/gob"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/pkg/errors"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	bolt "go.etcd.io/bbolt"
)

// startListener starts HTTP listener that will rotate the database
// and return it's contents
func startListener(addr string, db *dnsDB) error {
	if addr == "" {
		clog.Infof("No dnsdb HTTP listener configured")
		return nil
	}

	clog.Infof("Starting dnsdb HTTP listener on %s", addr)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &dbServer{
		db: db,
	}

	srv := &http.Server{Handler: server}
	go func() {
		_ = srv.Serve(ln)
	}()
	return nil
}

type dbServer struct {
	db *dnsDB
	sync.RWMutex
}

func (c *dbServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/csv" {
		http.Error(rw, "Not Found", http.StatusNotFound)
		return
	}

	// Disallow parallel requests as this request
	// changes the inner state of the DNSDB
	c.Lock()
	defer c.Unlock()

	// Flush the current buffer to the database
	c.db.Save()

	path, err := c.db.RotateDB()
	if err != nil {
		clog.Errorf("Failed to rotate DNSDB: %s", err)
		http.Error(rw, "Failed to rotate DNSDB", http.StatusInternalServerError)
		return
	}
	defer func() {
		// Remove the temporary database -- we don't need it anymore
		_ = os.Remove(path)
	}()

	// Now serve the content
	rw.Header().Set("Content-Type", "text/plain")

	var writer io.Writer
	writer = rw

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		rw.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(rw)
		defer gz.Close()
		writer = gz
	}

	rw.WriteHeader(http.StatusOK)
	err = dnsDBToCSV(path, writer)
	if err != nil {
		clog.Errorf("Failed to convert DB to CSV: %s", err)
	}
}

// dnsDBToCSV converts the DNSDB to CSV
func dnsDBToCSV(path string, writer io.Writer) error {
	db, err := bolt.Open(path, 0644, nil)
	if err != nil {
		return err
	}

	defer func() {
		_ = db.Close()
	}()

	return db.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(recordsBucket))
		if b == nil {
			return errors.New("records bucket not found")
		}

		csvWriter := csv.NewWriter(writer)
		defer csvWriter.Flush()

		// Iterating over all records
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			buf := bytes.NewBuffer(v)
			dec := gob.NewDecoder(buf)
			var recs []Record
			err := dec.Decode(&recs)
			if err != nil {
				clog.Errorf("Failed to decode DNSDB record: %s", err)
				// Don't interrupt - we'd better write other records
				continue
			}

			for _, r := range recs {
				csvRec := []string{
					r.DomainName,
					dns.TypeToString[r.RRType],
					dns.RcodeToString[r.RCode],
					r.Answer,
					strconv.FormatInt(r.Hits, 10),
				}
				err = csvWriter.Write(csvRec)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}
