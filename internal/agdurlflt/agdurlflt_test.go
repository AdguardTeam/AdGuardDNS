package agdurlflt_test

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/stretchr/testify/require"
)

// testRulesStrs are the common filtering rules for tests.
var testRulesStrs = []string{
	`||blocked.example^`,
	`@@||allowed.example^`,
	`||dnsrewrite.example^$dnsrewrite=192.0.2.1`,
}

// testRulesData is the data of [testRulesStrs] as bytes.
var testRulesData = []byte(strings.Join(testRulesStrs, "\n") + "\n")

func BenchmarkRulesToBytes(b *testing.B) {
	var got []byte

	b.ReportAllocs()
	for b.Loop() {
		got = agdurlflt.RulesToBytes(testRulesStrs)
	}

	require.Equal(b, testRulesData, got)

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkRulesToBytes-16    	 7925872	       145.3 ns/op	      96 B/op	       1 allocs/op
}

func BenchmarkRulesToBytesLower(b *testing.B) {
	var got []byte

	b.ReportAllocs()
	for b.Loop() {
		got = agdurlflt.RulesToBytesLower(testRulesStrs)
	}

	require.Equal(b, testRulesData, got)

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkRulesToBytesLower-16    	 1000000	      1188 ns/op	      96 B/op	       1 allocs/op
}
