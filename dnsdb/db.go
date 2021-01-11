package dnsdb

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
)

const recordsBucket = "Records"

type dnsDB struct {
	path string // path to the database file

	db     *bolt.DB
	buffer map[string][]Record

	bufferLock sync.Mutex
	dbLock     sync.Mutex
}

// NewDB creates a new instance of the DNSDB
func newDB(path string) (*dnsDB, error) {
	clog.Infof("Initializing DNSDB: %s", path)
	d := &dnsDB{
		path:   path,
		buffer: map[string][]Record{},
	}

	err := d.InitDB()
	if err != nil {
		return nil, err
	}
	clog.Infof("Finished initializing DNSDB: %s", path)
	return d, nil
}

// InitDB initializes the database file
func (d *dnsDB) InitDB() error {
	// database is always created from scratch
	_ = os.Remove(d.path)

	db, err := bolt.Open(d.path, 0644, nil)
	if err != nil {
		clog.Errorf("Failed to initialize existing DB: %s", err)
		return err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(recordsBucket))
		return err
	})

	if err != nil {
		clog.Errorf("Failed to create DB bucket: %s", err)
		return err
	}

	d.db = db
	return nil
}

// RotateDB closes the current DB, renames it to a temporary file,
// initializes a new empty DB, and returns the path to that temporary file
func (d *dnsDB) RotateDB() (string, error) {
	d.dbLock.Lock()
	defer d.dbLock.Unlock()

	err := d.db.Close()
	if err != nil {
		return "", err
	}

	// Moving the old DB to a new location before returning it
	tmpDir := os.TempDir()
	tmpPath := path.Join(tmpDir, path.Base(fmt.Sprintf("%s.%d", d.path, time.Now().Unix())))
	err = os.Rename(d.path, tmpPath)
	if err != nil {
		return "", err
	}

	// Re-creating the database
	err = d.InitDB()
	if err != nil {
		return "", err
	}

	dbSizeGauge.Set(0)
	dbRotateTimestamp.SetToCurrentTime()
	return tmpPath, nil
}

// RecordMsg saves a DNS response to the buffer
// this buffer will be then dumped to the database
func (d *dnsDB) RecordMsg(m *dns.Msg) {
	if !m.Response {
		// Not a response anyway
		return
	}
	if len(m.Question) != 1 {
		// Invalid DNS request
		return
	}

	q := m.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		// Only record A and AAAA
		return
	}
	if m.Rcode != dns.RcodeSuccess {
		// Discard unsuccessful responses
		return
	}

	name := strings.TrimSuffix(q.Name, ".")
	key := d.key(name, q.Qtype)

	d.bufferLock.Lock()
	if v, ok := d.buffer[key]; ok {
		// Increment hits count
		for i := 0; i < len(v); i++ {
			v[i].Hits++
		}
		d.bufferLock.Unlock()
		// Already buffered, doing nothing
		return
	}
	d.bufferLock.Unlock()

	records := d.toDBRecords(m, q)
	d.saveToBuffer(name, q.Qtype, records)
}

// Save - saves the buffered records to the local bolt database
func (d *dnsDB) Save() {
	clog.Infof("Saving the buffer to the DNSDB")
	start := time.Now()

	var buffer map[string][]Record

	// Copy the old buffer
	d.bufferLock.Lock()
	buffer = d.buffer
	d.buffer = map[string][]Record{}
	bufferSizeGauge.Set(0)
	d.bufferLock.Unlock()

	if len(buffer) == 0 {
		return
	}

	// Start writing
	d.dbLock.Lock()
	defer d.dbLock.Unlock()

	err := d.db.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(recordsBucket))

		for k, v := range buffer {
			dbKey := []byte(k)

			// First - look for existing records in the bucket
			val := b.Get(dbKey)
			if val != nil {
				recs, err := DecodeRecords(val)
				if err != nil || len(recs) == 0 {
					// Do nothing
					clog.Errorf("Failed to decode records for %s: %s", k, err)
				} else {
					// Use the "Hits" counter from the first record
					// to set the proper "Hits" count
					for _, r := range v {
						r.Hits = r.Hits + recs[0].Hits
					}
				}
			}

			// Now encode the records list
			dbValue, err := EncodeRecords(v)
			if err != nil {
				clog.Errorf("Failed to encode value for %s: %s", k, err)
				continue
			}

			// Save the updated list to the DB
			err = b.Put(dbKey, dbValue)
			if err != nil {
				clog.Errorf("Failed to save data for %s: %s", k, err)
			}
		}

		dbSizeGauge.Set(float64(b.Stats().KeyN))
		return nil
	})

	elapsedDBSave.Observe(time.Since(start).Seconds())

	if err != nil {
		clog.Errorf("Error while updating the DB: %s", err)
	}
}

func (d *dnsDB) saveToBuffer(name string, qtype uint16, records []Record) {
	d.bufferLock.Lock()
	d.buffer[d.key(name, qtype)] = records
	bufferSizeGauge.Inc()
	d.bufferLock.Unlock()
}

func (d *dnsDB) key(name string, qtype uint16) string {
	t, _ := dns.TypeToString[qtype]
	return name + "_" + t
}

// toDBRecords converts DNS message to an array to "record"
func (d *dnsDB) toDBRecords(m *dns.Msg, q dns.Question) []Record {
	if len(m.Answer) == 0 {
		rec := d.toDBRecord(m, q, nil)
		return []Record{rec}
	}

	records := []Record{}
	for _, rr := range m.Answer {
		rec := d.toDBRecord(m, q, rr)
		records = append(records, rec)
	}

	return records
}

func (d *dnsDB) toDBRecord(m *dns.Msg, q dns.Question, rr dns.RR) Record {
	rec := Record{}
	rec.DomainName = strings.TrimSuffix(q.Name, ".")
	rec.RCode = m.Rcode
	rec.Hits = 1
	if rr == nil {
		rec.RRType = q.Qtype
		rec.Answer = ""
	} else {
		rec.RRType = rr.Header().Rrtype

		switch v := rr.(type) {
		case *dns.CNAME:
			rec.Answer = strings.TrimSuffix(v.Target, ".")
		case *dns.A:
			rec.Answer = v.A.String()
		case *dns.AAAA:
			rec.Answer = v.AAAA.String()
		}
	}
	return rec
}
