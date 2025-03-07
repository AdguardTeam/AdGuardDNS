module github.com/AdguardTeam/AdGuardDNS

go 1.23.6

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.0.0-20240607112746-5690301129fe
	github.com/AdguardTeam/golibs v0.32.1
	github.com/AdguardTeam/urlfilter v0.20.0
	github.com/ameshkov/dnscrypt/v2 v2.3.0
	github.com/axiomhq/hyperloglog v0.2.3
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20231215233829-aa82cc1e6500
	github.com/caarlos0/env/v7 v7.1.0
	github.com/getsentry/sentry-go v0.31.1
	github.com/gomodule/redigo v1.9.2
	github.com/google/renameio/v2 v2.0.0
	github.com/miekg/dns v1.1.63
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/client_model v0.6.1
	github.com/prometheus/common v0.62.0
	github.com/quic-go/quic-go v0.49.0
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.32.0
	golang.org/x/exp v0.0.0-20250207012021-f9890c6ad9f3
	golang.org/x/net v0.34.0
	golang.org/x/sys v0.30.0
	golang.org/x/time v0.10.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.5
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/poly1305 v0.0.0-20180717145839-3fee0db0b635 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20250202011525-fc3143867406 // indirect
	github.com/kamstrup/intmap v0.5.1 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.22.2 // indirect
	github.com/panjf2000/ants/v2 v2.11.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/tools v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250204164813-702378808489 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver
