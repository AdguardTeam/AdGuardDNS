package agdtime_test

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
)

func ExampleLocation() {
	var req struct {
		TimeZone *agdtime.Location `json:"tmz"`
	}

	l, err := agdtime.LoadLocation("Europe/Brussels")
	if err != nil {
		panic(err)
	}

	req.TimeZone = l
	buf := &bytes.Buffer{}
	err = json.NewEncoder(buf).Encode(req)
	if err != nil {
		panic(err)
	}

	fmt.Print(buf)

	req.TimeZone = nil
	err = json.NewDecoder(buf).Decode(&req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", req)

	// Output:
	// {"tmz":"Europe/Brussels"}
	// {TimeZone:Europe/Brussels}
}
