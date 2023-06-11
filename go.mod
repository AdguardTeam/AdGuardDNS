module github.com/AdguardTeam/AdGuardDNS

go 1.20

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.100.0
	github.com/AdguardTeam/golibs v0.13.2
	github.com/AdguardTeam/urlfilter v0.16.1
	github.com/ameshkov/dnscrypt/v2 v2.2.5
	github.com/axiomhq/hyperloglog v0.0.0-20230201085229-3ddf4bad03dc
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20220606134207-859f65c6625b
	github.com/caarlos0/env/v7 v7.1.0
	github.com/getsentry/sentry-go v0.19.0
	github.com/google/renameio v1.0.1
	github.com/miekg/dns v1.1.52
	github.com/oschwald/maxminddb-golang v1.10.0
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.14.0
	github.com/prometheus/client_model v0.3.0
	github.com/prometheus/common v0.41.0
	github.com/quic-go/quic-go v0.35.1
	github.com/stretchr/testify v1.8.2
	go.etcd.io/bbolt v1.3.7
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	golang.org/x/net v0.8.0
	golang.org/x/sys v0.6.0
	golang.org/x/time v0.3.0
	google.golang.org/protobuf v1.30.0
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
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/pprof v0.0.0-20230228050547-1710fef4ab10 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/onsi/ginkgo/v2 v2.9.0 // indirect
	github.com/panjf2000/ants/v2 v2.7.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-19 v0.3.2 // indirect
	github.com/quic-go/qtls-go1-20 v0.2.2 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver
