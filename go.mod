module github.com/AdguardTeam/AdGuardDNS

go 1.13

require (
	github.com/AdguardTeam/urlfilter v0.10.0
	github.com/beefsack/go-rate v0.0.0-20180408011153-efa7637bb9b6
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/caddyserver/caddy v1.0.5
	github.com/coredns/coredns v1.6.9
	github.com/joomcode/errorx v1.0.1
	github.com/miekg/dns v1.1.31
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/stretchr/testify v1.5.1
	go.etcd.io/bbolt v1.3.4
	go.uber.org/atomic v1.6.0
	golang.org/x/net v0.0.0-20201021035429-f5854403a974
	golang.org/x/tools v0.0.0-20201028025901-8cd080b735b3 // indirect
)

replace github.com/coredns/coredns => github.com/ameshkov/coredns v1.2.5-0.20201214113603-34360d0c4346
