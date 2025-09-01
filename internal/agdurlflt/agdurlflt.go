// Package agdurlflt contains utilities for the urlfilter module.
package agdurlflt

import (
	"bytes"
	"unicode"
)

// RulesLen returns the length of the byte buffer necessary to write ruleStrs,
// separated by a newline, to it.
func RulesLen[S ~string](ruleStrs []S) (l int) {
	if len(ruleStrs) == 0 {
		return 0
	}

	for _, s := range ruleStrs {
		l += len(s) + len("\n")
	}

	return l
}

// RulesToBytes writes ruleStrs to a byte slice and returns it.
//
// TODO(a.garipov):  Consider moving to golibs or urlfilter.
func RulesToBytes[S ~string](ruleStrs []S) (b []byte) {
	l := RulesLen(ruleStrs)
	if l == 0 {
		return nil
	}

	buf := bytes.NewBuffer(make([]byte, 0, l))
	for _, s := range ruleStrs {
		_, _ = buf.WriteString(string(s))
		_ = buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// RulesToBytesLower writes lowercase versions of ruleStrs to a byte slice and
// returns it.
//
// NOTE:  Do not use this for rules that can include dnsrewrite modifiers, since
// their DNS types are case-sensitive.
//
// TODO(a.garipov):  Consider moving to golibs or urlfilter.
func RulesToBytesLower(ruleStrs []string) (b []byte) {
	l := RulesLen(ruleStrs)
	if l == 0 {
		return nil
	}

	buf := bytes.NewBuffer(make([]byte, 0, l))
	for _, s := range ruleStrs {
		for _, c := range s {
			// NOTE:  Theoretically there might be cases where a lowercase
			// version of a rune takes up more space or less space than an
			// uppercase one, but that doesn't matter since we're using a
			// bytes.Buffer and rules generally are ASCII-only.
			_, _ = buf.WriteRune(unicode.ToLower(c))
		}

		_ = buf.WriteByte('\n')
	}

	return buf.Bytes()
}
