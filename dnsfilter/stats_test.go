package dnsfilter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStats(t *testing.T) {
	stats = &Stats{
		FilterLists: map[int]map[string]int{},
	}

	recordRuleHit("||example.org^")
	recordRuleHit("||example.org^")
	recordRuleHit("||example.org^")
	recordRuleHit("||example.com^")

	b, err := json.Marshal(stats)
	assert.Nil(t, err)
	assert.Equal(t, `{"filters":{"15":{"||example.com^":1,"||example.org^":3}}}`, string(b))
	assert.Equal(t, int64(4), stats.RecordedHits)

	err = uploadStats()
	assert.Nil(t, err)
	assert.Equal(t, int64(0), stats.RecordedHits)
}
