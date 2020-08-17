package dnsdb

import (
	"bytes"
	"encoding/gob"
)

// Record of the DNS DB
type Record struct {
	DomainName string // DomainName -- fqdn version
	RRType     uint16 // RRType - either A, AAAA, or CNAME
	RCode      int    // RCode - DNS response RCode
	Answer     string // Answer - IP or hostname
	Hits       int64  // How many times this record was served
}

// EncodeRecords encodes an array of records to a byte array
func EncodeRecords(recs []Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(recs)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeRecords decodes an array of records from a byte array
func DecodeRecords(b []byte) ([]Record, error) {
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	var recs []Record
	err := dec.Decode(&recs)
	if err != nil {
		return nil, err
	}
	return recs, nil
}
