package dnsmsg_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
)

func ExampleBlockingModeCodec_MarshalJSON() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	fmt.Println("Custom IP:")
	err := enc.Encode(&dnsmsg.BlockingModeCodec{
		Mode: &dnsmsg.BlockingModeCustomIP{
			IPv4: netip.MustParseAddr("1.2.3.4"),
			IPv6: netip.MustParseAddr("1234::cdef"),
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Null IP:")
	err = enc.Encode(&dnsmsg.BlockingModeCodec{
		Mode: &dnsmsg.BlockingModeNullIP{},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("NXDOMAIN:")
	err = enc.Encode(&dnsmsg.BlockingModeCodec{
		Mode: &dnsmsg.BlockingModeNXDOMAIN{},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("REFUSED:")
	err = enc.Encode(&dnsmsg.BlockingModeCodec{
		Mode: &dnsmsg.BlockingModeREFUSED{},
	})
	if err != nil {
		panic(err)
	}

	// Output:
	// Custom IP:
	// {
	//   "ipv4": "1.2.3.4",
	//   "ipv6": "1234::cdef",
	//   "type": "custom_ip"
	// }
	// Null IP:
	// {
	//   "type": "null_ip"
	// }
	// NXDOMAIN:
	// {
	//   "type": "nxdomain"
	// }
	// REFUSED:
	// {
	//   "type": "refused"
	// }
}

func ExampleBlockingModeCodec_UnmarshalJSON() {
	c := &dnsmsg.BlockingModeCodec{}

	fmt.Println("Custom IP:")
	err := json.Unmarshal([]byte(`{
		"type":"custom_ip",
		"ipv4":"1.2.3.4",
		"ipv6":"1234::cdef"
	}`), c)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%T(%+[1]v)\n", c.Mode)

	fmt.Println("Null IP:")
	err = json.Unmarshal([]byte(`{
		"type":"null_ip"
	}`), c)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%T(%+[1]v)\n", c.Mode)

	fmt.Println("NXDOMAIN:")
	err = json.Unmarshal([]byte(`{
		"type":"nxdomain"
	}`), c)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%T(%+[1]v)\n", c.Mode)

	fmt.Println("REFUSED:")
	err = json.Unmarshal([]byte(`{
		"type":"refused"
	}`), c)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%T(%+[1]v)\n", c.Mode)

	// Output:
	// Custom IP:
	// *dnsmsg.BlockingModeCustomIP(&{IPv4:1.2.3.4 IPv6:1234::cdef})
	// Null IP:
	// *dnsmsg.BlockingModeNullIP(&{})
	// NXDOMAIN:
	// *dnsmsg.BlockingModeNXDOMAIN(&{})
	// REFUSED:
	// *dnsmsg.BlockingModeREFUSED(&{})
}

func ExampleBlockingModeCodec_UnmarshalJSON_invalid() {
	c := &dnsmsg.BlockingModeCodec{}

	err := json.Unmarshal([]byte(`{
		"type":"bad_type"
	}`), c)
	fmt.Println(err)

	err = json.Unmarshal([]byte(`{
		"type":"custom_ip"
	}`), c)
	fmt.Println(err)

	err = json.Unmarshal([]byte(`{
		"type":"custom_ip",
		"ipv4":"1234::cdef"
	}`), c)
	fmt.Println(err)

	err = json.Unmarshal([]byte(`{
		"type":"custom_ip",
		"ipv6":"1.2.3.4"
	}`), c)
	fmt.Println(err)

	// Output:
	// unexpected blocking mode type "bad_type"
	// bad options for blocking mode "custom_ip": ipv4 or ipv6 must be set
	// bad options for blocking mode "custom_ip": address "1234::cdef" is not ipv4
	// bad options for blocking mode "custom_ip": address "1.2.3.4" is not ipv6
}
