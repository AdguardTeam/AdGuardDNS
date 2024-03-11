module github.com/AdguardTeam/AdGuardDNS

go 1.21.8

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.0.0-00010101000000-000000000000
	github.com/AdguardTeam/golibs v0.20.1
	github.com/AdguardTeam/urlfilter v0.18.0
	github.com/ameshkov/dnscrypt/v2 v2.2.7
	github.com/axiomhq/hyperloglog v0.0.0-20240124082744-24bca3a5b39b
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20231215233829-aa82cc1e6500
	github.com/caarlos0/env/v7 v7.1.0
	github.com/getsentry/sentry-go v0.27.0
	github.com/google/renameio/v2 v2.0.0
	github.com/miekg/dns v1.1.58
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.18.0
	github.com/prometheus/client_model v0.5.0
	github.com/prometheus/common v0.46.0
	github.com/quic-go/quic-go v0.41.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/exp v0.0.0-20240213143201-ec583247a57a
	golang.org/x/net v0.21.0
	golang.org/x/sys v0.17.0
	golang.org/x/time v0.5.0
	google.golang.org/grpc v1.61.1
	google.golang.org/protobuf v1.32.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/poly1305 v0.0.0-20180717145839-3fee0db0b635 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/pprof v0.0.0-20240207164012-fb44976bdcd5 // indirect
	github.com/onsi/ginkgo/v2 v2.15.0 // indirect
	github.com/panjf2000/ants/v2 v2.9.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/mod v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.18.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240213162025-012b6fc9bca9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver
