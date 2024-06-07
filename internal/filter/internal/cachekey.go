package internal

import (
	"encoding/binary"
	"hash/maphash"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/mathutil"
)

// CacheKey is the cache key type for [NewCacheKey].
type CacheKey uint64

// hashSeed is the seed used by all hashes to create hash keys.
var hashSeed = maphash.MakeSeed()

// NewCacheKey produces a cache key based on host, qt, and isAns using the
// default algorithm.
func NewCacheKey(host string, qt dnsmsg.RRType, cl dnsmsg.Class, isAns bool) (k CacheKey) {
	// Use maphash explicitly instead of using a key structure to reduce
	// allocations and optimize interface conversion up the stack.
	h := &maphash.Hash{}
	h.SetSeed(hashSeed)

	_, _ = h.WriteString(host)

	// Save on allocations by reusing a buffer.
	var buf [5]byte
	binary.LittleEndian.PutUint16(buf[:2], qt)
	binary.LittleEndian.PutUint16(buf[2:4], cl)
	buf[4] = mathutil.BoolToNumber[byte](isAns)

	_, _ = h.Write(buf[:])

	return CacheKey(h.Sum64())
}
