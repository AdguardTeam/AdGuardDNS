package agdtime_test

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
)

func ExampleExponentialSchedule() {
	s := agdtime.NewExponentialSchedule(1*time.Second, 1*time.Minute, 2)

	for range 10 {
		fmt.Println(s.UntilNext(time.Time{}))
	}

	// Output:
	// 1s
	// 2s
	// 4s
	// 8s
	// 16s
	// 32s
	// 1m0s
	// 1m0s
	// 1m0s
	// 1m0s
}
