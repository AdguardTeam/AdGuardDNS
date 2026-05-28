package agdalg

import (
	"bytes"
	"unicode"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/unicode/rangetable"
)

// SkeletonConstructor constructs confusable skeletons from strings.  It's based
// on the [Unicode Technical Report #39].
//
// [Unicode Technical Report #39]: https://www.unicode.org/reports/tr39/#Confusable_Detection
type SkeletonConstructor struct {
	// transformerPool produces and allows reusing [transform.Transformer]s for
	// confusable skeleton construction.  The reusing is required since
	// [transform.Chain] allocates a stateful [transform.Transformer].
	transformerPool *syncutil.Pool[transform.Transformer]

	srcBufPool *syncutil.Pool[[]byte]
	dstBufPool *syncutil.Pool[[]byte]
}

// NewSkeletonConstructor returns a new properly initialized
// *SkeletonConstructor.  srcInitSize and dstInitSize are the initial sizes of
// the source and destination buffers for the skeleton construction.
func NewSkeletonConstructor(srcInitSize, dstInitSize uint) (sc *SkeletonConstructor) {
	return &SkeletonConstructor{
		transformerPool: syncutil.NewPool(newUTR39Chain),
		srcBufPool:      syncutil.NewSlicePool[byte](int(srcInitSize)),
		dstBufPool:      syncutil.NewSlicePool[byte](int(dstInitSize)),
	}
}

// Skeleton returns a confusable skeleton for s.  s is case-sensitive.
//
// TODO(e.burkov):  Consider rewriting the [transform.String] function to use
// buffers.  It will allow to avoid unnecessary allocations for the skeleton
// construction.
func (c *SkeletonConstructor) Skeleton(s string) (skel string) {
	trPtr := c.transformerPool.Get()
	defer c.transformerPool.Put(trPtr)

	(*trPtr).Reset()
	if s == "" {
		// Fast path for the common case for empty input.  Taken from
		// [transform.String].
		if _, _, err := (*trPtr).Transform(nil, nil, true); err == nil {
			return ""
		}
	}

	srcPtr := c.srcBufPool.Get()
	defer c.srcBufPool.Put(srcPtr)

	*srcPtr = append((*srcPtr)[:0], s...)

	dstPtr := c.dstBufPool.Get()
	defer c.dstBufPool.Put(dstPtr)

	var err error
	*dstPtr, _, err = transform.Append(*trPtr, (*dstPtr)[:0], *srcPtr)

	// It seems transformer can never return an error.
	//
	// TODO(e.burkov):  Consider sending to Sentry.
	errors.Check(err)

	if bytes.Equal(*srcPtr, *dstPtr) {
		return s
	}

	return string(*dstPtr)
}

// dicpTable is a merged table of all code points with the property
// Default_Ignorable_Code_Point.
//
// See https://www.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt.
//
// TODO(e.burkov):  Update to 16.0.0 when the [unicode] package will use it.
var dicpTable = rangetable.Merge(
	unicode.Other_Default_Ignorable_Code_Point,
	// These are ranges of Default_Ignorable_Code_Point excluding the ones
	// already included in [unicode.Other_Default_Ignorable_Code_Point].
	&unicode.RangeTable{
		R16: []unicode.Range16{{
			// SOFT HYPHEN.
			Lo: 0x00AD,
			// ARABIC LETTER MARK.
			Hi: 0x061C,
			// Only include two code points.
			Stride: (0x061C - 0x00AD),
		}, {
			// MONGOLIAN FREE VARIATION SELECTOR ONE.
			Lo: 0x180B,
			// MONGOLIAN FREE VARIATION SELECTOR THREE.
			Hi: 0x180D,
			// Include all 3 code points.
			Stride: 1,
		}, {
			// MONGOLIAN VOWEL SEPARATOR.
			Lo: 0x180E,
			// MONGOLIAN FREE VARIATION SELECTOR FOUR.
			Hi: 0x180F,
			// Include all 2 code points.
			Stride: 1,
		}, {
			// ZERO WIDTH SPACE.
			Lo: 0x200B,
			// RIGHT-TO-LEFT MARK.
			Hi: 0x200F,
			// Include all 5 code points.
			Stride: 1,
		}, {
			// LEFT-TO-RIGHT EMBEDDING.
			Lo: 0x202A,
			// RIGHT-TO-LEFT OVERRIDE.
			Hi: 0x202E,
			// Include all 5 code points.
			Stride: 1,
		}, {
			// WORD JOINER.
			Lo: 0x2060,
			// INVISIBLE PLUS.
			Hi: 0x2064,
			// Include all 5 code points.
			Stride: 1,
		}, {
			// LEFT-TO-RIGHT ISOLATE.
			Lo: 0x2066,
			// NOMINAL DIGIT SHAPES.
			Hi: 0x206F,
			// Include all 10 code points.
			Stride: 1,
		}, {
			// VARIATION SELECTOR-1.
			Lo: 0xFE00,
			// VARIATION SELECTOR-16.
			Hi: 0xFE0F,
			// Include all 16 code points.
			Stride: 1,
		}, {
			// ZERO WIDTH NO-BREAK SPACE.
			Lo: 0xFEFF,
			// HALFWIDTH HANGUL FILLER.
			Hi: 0xFFA0,
			// Only include two code points.
			Stride: (0xFFA0 - 0xFEFF),
		}},
		R32: []unicode.Range32{{
			// SHORTHAND FORMAT LETTER OVERLAP.
			Lo: 0x1BCA0,
			// SHORTHAND FORMAT UP STEP.
			Hi: 0x1BCA3,
			// Include all 4 code points.
			Stride: 1,
		}, {
			// MUSICAL SYMBOL BEGIN BEAM.
			Lo: 0x1D173,
			// MUSICAL SYMBOL END PHRASE.
			Hi: 0x1D17A,
			// Include all 8 code points.
			Stride: 1,
		}, {
			// LANGUAGE TAG.
			Lo: 0xE0001,
			// Reserved.
			Hi: 0xE0002,
			// Include all 2 code points.
			Stride: 1,
		}, {
			// TAG SPACE.
			Lo: 0xE0020,
			// CANCEL TAG.
			Hi: 0xE007F,
			// Include all 96 code points.
			Stride: 1,
		}, {
			// VARIATION SELECTOR-17.
			Lo: 0xE0100,
			// VARIATION SELECTOR-256.
			Hi: 0xE01EF,
			// Include all 240 code points.
			Stride: 1,
		}},
	},
)

// dicpRemover is a [transform.Transformer] that removes all runes with the
// Default_Ignorable_Code_Point property.
var dicpRemover = runes.Remove(runes.In(dicpTable))

// newUTR39Chain is a helper function for creating a new chain of transformers
// for the [UTR #39] confusable skeleton construction.
//
// [UTR #39]: https://www.unicode.org/reports/tr39/#Confusable_Detection
func newUTR39Chain() (tr *transform.Transformer) {
	return new(transform.Chain(
		norm.NFD,
		dicpRemover,
		confusablePrototyper,
		norm.NFD,
	))
}
