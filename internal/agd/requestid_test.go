package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/stretchr/testify/require"
)

func BenchmarkNewRequestID(b *testing.B) {
	var reqID agd.RequestID

	b.ReportAllocs()
	for b.Loop() {
		reqID = agd.NewRequestID()
	}

	require.NotEmpty(b, reqID)

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agd
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkNewRequestID-12    	41978553	        27.96 ns/op	       0 B/op	       0 allocs/op
}
