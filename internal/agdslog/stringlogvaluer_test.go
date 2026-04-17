package agdslog_test

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdslog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
)

// stringer is a [fmt.Stringer] implementation for tests.
//
// TODO(a.garipov): Consider adding to golibs.
type stringer struct {
	onString func() (s string)
}

// type check
var _ fmt.Stringer = (*stringer)(nil)

// String implements the [fmt.Stringer] interface for *stringer.
func (s *stringer) String() string {
	return s.onString()
}

// newTestStringer returns a [fmt.Stringer] implementation that does nothing and
// panics in [fmt.Stringer.String].
func newTestStringer() (s *stringer) {
	return &stringer{
		onString: func() (str string) { panic(testutil.UnexpectedCall()) },
	}
}

func Benchmark_StringLogValuer(b *testing.B) {
	const (
		logMsg  = "msg"
		attrKey = "str"
	)

	stringer := newTestStringer()

	data := []byte("a")
	stringer.onString = func() (s string) {
		return string(data)
	}

	l := slogutil.New(&slogutil.Config{
		Format: slogutil.FormatJSONHybrid,
		Output: io.Discard,
		Level:  slog.LevelInfo,
	})

	b.Run("log_valuer_disabled_log_level", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			l.Debug(logMsg, attrKey, agdslog.NewStringerValuer(stringer))
		}
	})

	b.Run("log_valuer_enabled_log_level", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			l.Info(logMsg, attrKey, agdslog.NewStringerValuer(stringer))
		}
	})

	b.Run("string_call_disabled_log_level", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			l.Debug(logMsg, attrKey, stringer.String())
		}
	})

	b.Run("string_call_enabled_log_level", func(b *testing.B) {
		b.ReportAllocs()

		for b.Loop() {
			l.Info(logMsg, attrKey, stringer.String())
		}
	})

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdslog
	//	cpu: AMD Ryzen AI 7 PRO 350 w/ Radeon 860M
	//	Benchmark_StringLogValuer/log_valuer_disabled_log_level-16              247510198                4.565 ns/op           0 B/op          0 allocs/op
	//	Benchmark_StringLogValuer/log_valuer_enabled_log_level-16                1594588               753.5 ns/op            72 B/op          2 allocs/op
	//	Benchmark_StringLogValuer/string_call_disabled_log_level-16             56316349                22.79 ns/op           16 B/op          1 allocs/op
	//	Benchmark_StringLogValuer/string_call_enabled_log_level-16               1451767               807.9 ns/op            88 B/op          3 allocs/op
}
