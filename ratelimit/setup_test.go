package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy"
)

func TestSetup(t *testing.T) {
	l := testStartConsulService()
	defer func() { _ = l.Close() }()

	for i, testcase := range []struct {
		config  string
		failing bool
	}{
		{`ratelimit`, false},
		{`ratelimit 100`, false},
		{`ratelimit { 
					whitelist 127.0.0.1
				}`, false},
		{`ratelimit 50 {
					whitelist 127.0.0.1 176.103.130.130
				}`, false},
		{`ratelimit test`, true},
		{fmt.Sprintf(`ratelimit 50 {
					whitelist 127.0.0.1 176.103.130.130
					consul http://127.0.0.1:%d/v1/catalog/service/test 123
				}`, l.Addr().(*net.TCPAddr).Port), false},
	} {
		c := caddy.NewTestController("dns", testcase.config)
		c.ServerBlockKeys = []string{""}
		err := setup(c)
		if err != nil {
			if !testcase.failing {
				t.Fatalf("Test #%d expected no errors, but got: %v", i, err)
			}
			continue
		}
		if testcase.failing {
			t.Fatalf("Test #%d expected to fail but it didn't", i)
		}
	}
}

func testStartConsulService() net.Listener {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/catalog/service/test", func(w http.ResponseWriter, r *http.Request) {
		content := `[{
    "ID": "5c6183d2-20fe-7615-d49e-080000000025",
    "Node": "some-host-name",
    "Address": "123.123.123.123",
    "Datacenter": "eu",
    "TaggedAddresses": {
        "lan": "123.123.123.123",
        "wan": "123.123.123.123"
    },
    "NodeMeta": {},
    "ServiceKind": "",
    "ServiceID": "test",
    "ServiceName": "test",
    "ServiceTags": ["prod"],
    "ServiceAddress": "",
    "ServiceWeights": {
        "Passing": 1,
        "Warning": 1
    },
    "ServiceMeta": {},
    "ServicePort": 1987,
    "ServiceEnableTagOverride": false,
    "ServiceProxyDestination": "",
    "ServiceProxy": {},
    "ServiceConnect": {},
    "CreateIndex": 1584089033,
    "ModifyIndex": 1584089033
},{
    "ID": "5c6183d2-20fe-7615-d49e-080000000026",
    "Node": "some-host-name2",
    "Address": "123.123.123.122",
    "Datacenter": "eu",
    "TaggedAddresses": {
        "lan": "123.123.123.122",
        "wan": "123.123.123.122"
    },
    "NodeMeta": {},
    "ServiceKind": "",
    "ServiceID": "test",
    "ServiceName": "test",
    "ServiceTags": ["prod"],
    "ServiceAddress": "",
    "ServiceWeights": {
        "Passing": 1,
        "Warning": 1
    },
    "ServiceMeta": {},
    "ServicePort": 1987,
    "ServiceEnableTagOverride": false,
    "ServiceProxyDestination": "",
    "ServiceProxy": {},
    "ServiceConnect": {},
    "CreateIndex": 1584089033,
    "ModifyIndex": 1584089033
}]`
		_, _ = w.Write([]byte(content))
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	srv := &http.Server{Handler: mux}

	go func() { _ = srv.Serve(listener) }()
	return listener
}
