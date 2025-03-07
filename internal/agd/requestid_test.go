package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/stretchr/testify/require"
)

var reqIDSink agd.RequestID

func BenchmarkNewRequestID(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		reqIDSink = agd.NewRequestID()
	}

	require.NotEmpty(b, reqIDSink)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agd
	//	cpu: Apple M1 Pro
	//	BenchmarkNewRequestID-8   	56177144	        21.33 ns/op	       0 B/op	       0 allocs/op
}
