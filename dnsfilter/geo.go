package dnsfilter

import (
	"net"
	"os"
	"sync"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	geoip2 "github.com/oschwald/geoip2-golang"
)

// geoIP - global struct that holds GeoIP settings
var geoIP = &GeoIP{}

// geoIPReloadCheckPeriod is a period that we use
// if geoIP database has been changed
const geoIPReloadCheckPeriod = time.Hour * 24

type GeoIP struct {
	dbPath string

	reader      *geoip2.Reader
	lastModTime time.Time
	sync.RWMutex
}

func initGeoIP(settings plugSettings) error {
	if settings.GeoIPPath == "" {
		return nil
	}

	if geoIP.reader != nil {
		// Already initialized
		clog.Info("GeoIP database has been already initialized")
		return nil
	}
	clog.Infof("Initializing GeoIP database: %s", settings.GeoIPPath)

	geoIP.dbPath = settings.GeoIPPath
	fi, err := os.Stat(geoIP.dbPath)
	if err != nil {
		return err
	}
	geoIP.lastModTime = fi.ModTime()

	r, err := geoip2.Open(settings.GeoIPPath)
	if err != nil {
		return err
	}

	geoIP.reader = r

	go func() {
		for range time.Tick(geoIPReloadCheckPeriod) {
			geoIP.reload()
		}
	}()

	clog.Infof("GeoIP database has been initialized")
	return nil
}

// getGeoData - gets geo data of the request IP
// returns false if it cannot be determined
// returns bool, country, continent
func (g *GeoIP) getGeoData(w dns.ResponseWriter) (bool, string, string) {
	if geoIP.reader == nil {
		return false, "", ""
	}

	g.RLock()
	defer g.RUnlock()

	var ip net.IP

	addr := w.RemoteAddr()
	switch v := addr.(type) {
	case *net.TCPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		return false, "", ""
	}

	c, err := geoIP.reader.Country(ip)
	if err != nil {
		clog.Errorf("failed to do the GeoIP lookup: %v", err)
		return false, "", ""
	}

	country := c.Country.IsoCode
	continent := c.Continent.Code
	return true, country, continent
}

// reload - periodically checks if we should reload GeoIP database
func (g *GeoIP) reload() {
	fi, err := os.Stat(g.dbPath)
	if err != nil {
		clog.Errorf("failed to check GeoIP file state: %v", err)
		return
	}

	lastModTime := fi.ModTime()
	if !lastModTime.After(g.lastModTime) {
		return
	}

	clog.Info("Reloading GeoIP database")
	r, err := geoip2.Open(geoIP.dbPath)
	if err != nil {
		clog.Errorf("failed to load new GeoIP database: %v", err)
	}

	g.Lock()
	geoIP.reader = r
	geoIP.lastModTime = lastModTime
	g.Unlock()
	clog.Info("GeoIP database has been reloaded")
}
