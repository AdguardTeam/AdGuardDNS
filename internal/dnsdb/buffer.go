package dnsdb

import (
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/miekg/dns"
)

// buffer contains the approximate statistics for DNS answers.  It saves data
// until it reaches maxSize, upon which it can only increase the hits of the
// previous records.
type buffer struct {
	// mu protects entries.
	mu *sync.Mutex

	// entries is the data of the statistics.
	entries map[recordKey]*recordValue

	// maxSize is the maximum length of entries.
	maxSize int
}

// add increments the records for all answers.
func (b *buffer) add(target string, answers []dns.RR, qt dnsmsg.RRType, rc dnsmsg.RCode) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Do nothing if the buffer is already full.
	l := len(b.entries)
	if l >= b.maxSize {
		return
	}

	key := recordKey{
		target: target,
		qt:     qt,
	}

	prev, ok := b.entries[key]
	if ok {
		prev.hits++

		// Note, that only the first set of answers is stored in the buffer.
		// If a more detailed response is needed, maps.Copy can be used to
		// achieve that.

		return
	}

	b.entries[key] = &recordValue{
		answers: toAnswerSet(answers, rc),
		hits:    1,
	}

	metrics.DNSDBBufferSize.Set(float64(l + 1))
}

// all returns buffered records.
func (b *buffer) all() (records []*record) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for key, val := range b.entries {
		if len(val.answers) == 0 {
			records = append(records, &record{
				target: key.target,
				hits:   val.hits,
				rrType: key.qt,
			})

			continue
		}

		for a := range val.answers {
			records = append(records, &record{
				target: key.target,
				answer: a.value,
				hits:   val.hits,
				rrType: a.rrType,
				rcode:  a.rcode,
			})
		}
	}

	return records
}

// toAnswerSet converts a slice of [dns.RR] to a map that can easier be
// serialized to a csv.
func toAnswerSet(answers []dns.RR, rc dnsmsg.RCode) (answerSet map[recordAnswer]unit) {
	answerSet = map[recordAnswer]unit{}
	for _, a := range answers {
		ansStr := answerString(a)
		if ansStr != "" {
			answerSet[recordAnswer{
				value:  ansStr,
				rrType: a.Header().Rrtype,
				rcode:  rc,
			}] = unit{}
		}
	}

	return answerSet
}
