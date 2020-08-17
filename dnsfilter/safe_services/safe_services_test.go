package safeservices

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareData(t *testing.T) {
	// fill with test data
	hashes := make([]byte, 30*5)
	i := 0
	copy(hashes[i:i+30], []byte("123456789012345678901234567898"))
	i += 30
	copy(hashes[i:i+30], []byte("123456789012345678901234567894"))
	i += 30
	copy(hashes[i:i+30], []byte("123456789012345678901234567896"))
	i += 30
	copy(hashes[i:i+30], []byte("123456789012345678901234567892"))
	i += 30
	copy(hashes[i:i+30], []byte("123456789012345678901234567890"))

	// sort
	hashSorter := hashSort{data: hashes}
	sort.Sort(&hashSorter)
	hashes = hashSorter.data

	// check sorting
	i = 0
	assert.Equal(t, "123456789012345678901234567890", string(hashes[i:i+30]))
	i += 30
	assert.Equal(t, "123456789012345678901234567892", string(hashes[i:i+30]))
	i += 30
	assert.Equal(t, "123456789012345678901234567894", string(hashes[i:i+30]))
	i += 30
	assert.Equal(t, "123456789012345678901234567896", string(hashes[i:i+30]))
	i += 30
	assert.Equal(t, "123456789012345678901234567898", string(hashes[i:i+30]))
	i += 30

	assert.False(t, searchHash(hashes, []byte("123456789012345678901234567891")))
	assert.True(t, searchHash(hashes, []byte("123456789012345678901234567890")))
	assert.True(t, searchHash(hashes, []byte("123456789012345678901234567892")))
	assert.True(t, searchHash(hashes, []byte("123456789012345678901234567894")))
	assert.True(t, searchHash(hashes, []byte("123456789012345678901234567896")))
	assert.True(t, searchHash(hashes, []byte("123456789012345678901234567898")))
}
