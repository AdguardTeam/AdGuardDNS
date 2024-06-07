module github.com/AdguardTeam/AdGuardDNS

go 1.22.4

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.0.0-00010101000000-000000000000
	github.com/AdguardTeam/golibs v0.23.2
	github.com/AdguardTeam/urlfilter v0.18.0
	github.com/ameshkov/dnscrypt/v2 v2.3.0
	github.com/axiomhq/hyperloglog v0.0.0-20240319100328-84253e514e02
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20231215233829-aa82cc1e6500
	github.com/caarlos0/env/v7 v7.1.0
	github.com/getsentry/sentry-go v0.27.0
	github.com/google/renameio/v2 v2.0.0
	github.com/miekg/dns v1.1.58
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.19.0
	github.com/prometheus/client_model v0.6.1
	github.com/prometheus/common v0.52.3
	github.com/quic-go/quic-go v0.42.0
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.22.0
	golang.org/x/exp v0.0.0-20240409090435-93d18d7e34b8
	golang.org/x/net v0.24.0
	golang.org/x/sys v0.19.0
	golang.org/x/time v0.5.0
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/poly1305 v0.0.0-20180717145839-3fee0db0b635 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20240409012703-83162a5b38cd // indirect
	github.com/onsi/ginkgo/v2 v2.17.1 // indirect
	github.com/panjf2000/ants/v2 v2.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.13.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.20.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240412170617-26222e5d3d56 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver
