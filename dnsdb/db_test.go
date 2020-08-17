package dnsdb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDbRotateAndSave(t *testing.T) {
	path := filepath.Join(os.TempDir(), "db.bin")
	defer func() {
		_ = os.Remove(path)
	}()

	db, err := newDB(path)
	assert.Nil(t, err)
	assert.NotNil(t, db)

	// Test DNS message
	m := new(dns.Msg)
	m.SetQuestion("badhost.", dns.TypeA)
	res := new(dns.Msg)
	res.SetReply(m)
	res.Response, m.RecursionAvailable = true, true

	res.Answer = []dns.RR{
		test.A("badhost. 0 IN A 37.220.26.135"),
	}

	// Record this message twice
	db.RecordMsg(res)
	db.RecordMsg(res)

	// Check buffer size
	assert.Equal(t, 1, len(db.buffer))

	// Save to the DB
	db.Save()

	// Rotate
	dbPath, err := db.RotateDB()
	assert.Nil(t, err)
	defer func() {
		_ = os.Remove(dbPath)
	}()

	// Write CSV
	buf := bytes.NewBufferString("")
	err = dnsDBToCSV(dbPath, buf)
	assert.Nil(t, err)

	// Check CSV
	assert.Equal(t, "badhost,A,NOERROR,37.220.26.135,2\n", buf.String())
}
