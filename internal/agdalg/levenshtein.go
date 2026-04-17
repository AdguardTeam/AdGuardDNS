package agdalg

import (
	"slices"
	"strings"

	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/syncutil"
)

// DamerauLevenshteinCalculator calculates the Damerau–Levenshtein distance
// between ASCII strings.
type DamerauLevenshteinCalculator struct {
	rowsPool *syncutil.Pool[[]uint]
}

// NewDamerauLevenshteinCalculator returns a new properly initialized
// *DamerauLevenshteinCalculator.  initLen is the initial length for the
// internal buffers.
func NewDamerauLevenshteinCalculator(initLen int) (c *DamerauLevenshteinCalculator) {
	return &DamerauLevenshteinCalculator{
		rowsPool: syncutil.NewSlicePool[uint](initLen),
	}
}

// Distance calculates the Damerau–Levenshtein distance between a and b while
// allocating as little as possible.  Currently, it only supports ASCII strings,
// so a and b must only contain those characters.  It is safe for concurrent
// use.
//
// See:
//   - https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance
//   - https://en.wikipedia.org/wiki/Wagner%E2%80%93Fischer_algorithm
//
// TODO(a.garipov):  Add support for limiting the distance.
func (c *DamerauLevenshteinCalculator) Distance(a, b string) (dist uint) {
	dist, ok := c.handleQuick(a, b)
	if ok {
		return dist
	}

	// Prepare the rows and make sure they have the proper length.
	//
	// NOTE:  It seems like it doesn't matter whether to take the longer or the
	// shorter length.
	rowLen := len(b) + 1

	curr, currPtr := c.newRow(rowLen)
	defer c.rowsPool.Put(currPtr)

	prev, prevPtr := c.newRow(rowLen)
	defer c.rowsPool.Put(prevPtr)

	// prevPrev is the N-2th row used to calculate the distance when a
	// transposition happens.
	prevPrev, prevPrevPtr := c.newRow(rowLen)
	defer c.rowsPool.Put(prevPrevPtr)

	for i := range prev {
		prev[i] = uint(i)
	}

	for i := range a {
		// Set the initial distance to the cost of deleting i+1 bytes from the
		// string.
		curr[0] = uint(i + 1)

		for j := range b {
			// Calculate the minimum cost between deletion, insertion, and
			// substitution.
			costDel := prev[j+1] + 1
			costIns := curr[j] + 1

			sub := mathutil.BoolToNumber[uint](a[i] != b[j])
			costSub := prev[j] + sub

			costTrans := costSub
			if hasTransposition(a, b, i, j) {
				costTrans = prevPrev[j-1] + sub
			}

			curr[j+1] = min(costDel, costIns, costSub, costTrans)
		}

		// Swap the rows for the next iteration.
		prevPrev, prev, curr = prev, curr, prevPrev
	}

	return prev[len(b)]
}

// hasTransposition returns true if a and b have transposed characters at
// indexes i and j.  i and j must be within the lengths of a and b respectively.
func hasTransposition(a, b string, i, j int) (ok bool) {
	return i > 0 &&
		j > 0 &&
		a[i] == b[j-1] &&
		a[i-1] == b[j]
}

// handleQuick is a helper method that uses simple checks for some common
// patterns of distance.  If ok is true, dist is the calculated distance.
func (*DamerauLevenshteinCalculator) handleQuick(a, b string) (dist uint, ok bool) {
	ok = true

	switch {
	case a == b:
		// Go on, the distance is zero.
	case a == "":
		dist = uint(len(b))
	case b == "":
		dist = uint(len(a))
	case strings.Contains(a, b):
		dist = uint(len(a) - len(b))
	case strings.Contains(b, a):
		dist = uint(len(b) - len(a))
	default:
		ok = false
	}

	return dist, ok
}

// newRow returns a new row with the given length from the pool as well as a
// pointer to return to the pool after using it.  row is guaranteed to have the
// length l.
func (c *DamerauLevenshteinCalculator) newRow(l int) (row []uint, ptr *[]uint) {
	ptr = c.rowsPool.Get()

	if cap(*ptr) < l {
		*ptr = slices.Grow(*ptr, l-len(*ptr))
	}

	row = (*ptr)[:l]

	return row, ptr
}
