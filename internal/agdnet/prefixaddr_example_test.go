package agdnet_test

import (
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
)

func ExamplePrefixNetAddr_string() {
	fmt.Println(&agdnet.PrefixNetAddr{
		Prefix: netip.MustParsePrefix("1.2.3.4/32"),
		Net:    "",
		Port:   5678,
	})
	fmt.Println(&agdnet.PrefixNetAddr{
		Prefix: netip.MustParsePrefix("1.2.3.0/24"),
		Net:    "",
		Port:   5678,
	})

	// Output:
	// 1.2.3.4:5678
	// 1.2.3.0:5678/24
}
