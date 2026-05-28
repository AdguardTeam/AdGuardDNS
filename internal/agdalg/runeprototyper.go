package agdalg

import (
	"unicode/utf8"

	"golang.org/x/text/transform"
)

// runePrototyper is a [transform.Transformer] that replaces each rune with
// a sequence of bytes.
//
// TODO(e.burkov):  Implement [transform.SpanningTransformer]
type runePrototyper struct {
	transform.NopResetter

	prototypes [][]byte
}

// type check
var _ transform.Transformer = (*runePrototyper)(nil)

// Transform implements the [transform.Transformer] interface for
// *runePrototyper.  It replaces each rune in src with sequence of its
// prototypes.
func (rp *runePrototyper) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		r, size := utf8.DecodeRune(src[nSrc:])
		if r == utf8.RuneError && size == 1 && !atEOF && !utf8.FullRune(src[nSrc:]) {
			return nDst, nSrc, transform.ErrShortSrc
		}

		prototype := rp.prototype(r)
		if prototype == nil {
			prototype = src[nSrc : nSrc+size]
		}

		if nDst+len(prototype) > len(dst) {
			return nDst, nSrc, transform.ErrShortDst
		}

		nDst += copy(dst[nDst:], prototype)
		nSrc += size
	}

	return nDst, nSrc, nil
}

// prototype returns the prototype of r.  If r has no prototype, it returns nil.
func (rp *runePrototyper) prototype(r rune) (prototype []byte) {
	if idx := int(r); idx >= 0 && idx < len(rp.prototypes) {
		prototype = rp.prototypes[idx]
	}

	return prototype
}
