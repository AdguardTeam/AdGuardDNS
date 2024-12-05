module github.com/AdguardTeam/AdGuardDNS

go 1.23.4

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.0.0-20240607112746-5690301129fe
	github.com/AdguardTeam/golibs v0.30.4
	github.com/AdguardTeam/urlfilter v0.20.0
	github.com/ameshkov/dnscrypt/v2 v2.3.0
	github.com/axiomhq/hyperloglog v0.2.0
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20231215233829-aa82cc1e6500
	github.com/caarlos0/env/v7 v7.1.0
	github.com/getsentry/sentry-go v0.29.1
	github.com/gomodule/redigo v1.9.2
	github.com/google/renameio/v2 v2.0.0
	github.com/miekg/dns v1.1.62
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/client_model v0.6.1
	github.com/prometheus/common v0.60.1
	github.com/quic-go/quic-go v0.48.2
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.30.0
	golang.org/x/exp v0.0.0-20241204233417-43b7b7cde48d
	golang.org/x/net v0.32.0
	golang.org/x/sys v0.28.0
	golang.org/x/time v0.8.0
	google.golang.org/grpc v1.68.0
	google.golang.org/protobuf v1.35.1
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
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20241203143554-1e3fdc7de467 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.22.0 // indirect
	github.com/panjf2000/ants/v2 v2.10.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver
