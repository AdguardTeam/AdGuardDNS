package dnsdb

import (
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/container"
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

// add adds a new record to the buffer or updates the number of hits on the
// stored record.  count is the total number of records stored, ok is true if
// the new record was added.
func (b *buffer) add(
	target string,
	answers []dns.RR,
	qt dnsmsg.RRType,
	rc dnsmsg.RCode,
) (count int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Do nothing if the buffer is already full.
	count = len(b.entries)
	if count >= b.maxSize {
		return count, false
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

		return count, false
	}

	b.entries[key] = &recordValue{
		answers: toAnswerSet(answers, rc),
		hits:    1,
	}

	return count + 1, true
}

// all returns buffered records.
func (b *buffer) all() (records []*record) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for key, val := range b.entries {
		if val.answers.Len() == 0 {
			records = append(records, &record{
				target: key.target,
				hits:   val.hits,
				rrType: key.qt,
			})

			continue
		}

		val.answers.Range(func(a recordAnswer) (cont bool) {
			records = append(records, &record{
				target: key.target,
				answer: a.value,
				hits:   val.hits,
				rrType: a.rrType,
				rcode:  a.rcode,
			})

			return true
		})
	}

	return records
}

// toAnswerSet converts a slice of [dns.RR] to a set that can easier be
// serialized to a csv.
func toAnswerSet(answers []dns.RR, rc dnsmsg.RCode) (answerSet *container.MapSet[recordAnswer]) {
	answerSet = container.NewMapSet[recordAnswer]()
	for _, a := range answers {
		ansStr := answerString(a)
		if ansStr != "" {
			answerSet.Add(recordAnswer{
				value:  ansStr,
				rrType: a.Header().Rrtype,
				rcode:  rc,
			})
		}
	}

	return answerSet
}
