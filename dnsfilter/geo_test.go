package dnsfilter

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/stretchr/testify/assert"
)

type TestGeoWriter struct {
	addr net.Addr
	dns.ResponseWriter
}

func (w *TestGeoWriter) RemoteAddr() net.Addr {
	return w.addr
}

func TestGeoIP(t *testing.T) {
	settings := plugSettings{
		GeoIPPath: "../tests/GeoIP2-Country-Test.mmdb",
	}

	err := initGeoIP(settings)
	assert.Nil(t, err)

	ok, country, continent := geoIP.getGeoData(&TestGeoWriter{
		addr: &net.TCPAddr{IP: net.IP{127, 0, 0, 1}},
	})

	assert.True(t, ok)
	assert.Equal(t, "", country)
	assert.Equal(t, "", continent)

	ok, country, continent = geoIP.getGeoData(&TestGeoWriter{
		addr: &net.TCPAddr{IP: net.IP{81, 2, 69, 142}},
	})

	assert.True(t, ok)
	assert.Equal(t, "GB", country)
	assert.Equal(t, "EU", continent)
}
