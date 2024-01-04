module github.com/AdguardTeam/AdGuardDNS

go 1.21.5

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.0.0-00010101000000-000000000000
	github.com/AdguardTeam/golibs v0.18.1
	github.com/AdguardTeam/urlfilter v0.17.2
	github.com/ameshkov/dnscrypt/v2 v2.2.7
	github.com/axiomhq/hyperloglog v0.0.0-20230201085229-3ddf4bad03dc
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20220606134207-859f65c6625b
	github.com/caarlos0/env/v7 v7.1.0
	github.com/getsentry/sentry-go v0.25.0
	github.com/google/renameio/v2 v2.0.0
	github.com/miekg/dns v1.1.56
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.17.0
	github.com/prometheus/client_model v0.5.0
	github.com/prometheus/common v0.44.0
	github.com/quic-go/quic-go v0.39.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	golang.org/x/net v0.17.0
	golang.org/x/sys v0.13.0
	golang.org/x/time v0.3.0
	google.golang.org/grpc v1.58.3
	google.golang.org/protobuf v1.31.0
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
	github.com/google/pprof v0.0.0-20230926050212-f7f687d19a98 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/onsi/ginkgo/v2 v2.13.0 // indirect
	github.com/panjf2000/ants/v2 v2.8.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.3.4 // indirect
	go.uber.org/mock v0.3.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/mod v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/tools v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231009173412-8bfb1ae86b6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver
