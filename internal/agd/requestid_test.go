package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/stretchr/testify/require"
)

var reqIDSink agd.RequestID

func BenchmarkNewRequestID(b *testing.B) {
	agd.InitRequestID()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqIDSink = agd.NewRequestID()
	}

	require.NotEmpty(b, reqIDSink)

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agd
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkNewRequestID-16        50985721                24.91 ns/op            0 B/op          0 allocs/op
}
