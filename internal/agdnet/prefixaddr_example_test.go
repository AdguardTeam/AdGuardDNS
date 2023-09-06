package agdnet_test

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

func ExampeFormatPrefixAddr() {
	fmt.Println(agdnet.FormatPrefixAddr(netip.MustParsePrefix("1.2.3.4/32"), 5678))
	fmt.Println(agdnet.FormatPrefixAddr(netip.MustParsePrefix("1.2.3.0/24"), 5678))

	// Output:
	// 1.2.3.4:5678
	// 1.2.3.0:5678/24
}
