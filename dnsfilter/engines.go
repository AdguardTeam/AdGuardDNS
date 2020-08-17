package dnsfilter

import (
	"sync"

	safeservices "github.com/AdguardTeam/AdGuardDNS/dnsfilter/safe_services"
	"github.com/AdguardTeam/urlfilter"
)

// Filtering engines are stored in this global map in order to avoid
// excessive memory usage.
// The key is path to the file with blocking rules.
var enginesMap = make(map[string]*engineInfo)
var enginesMapGuard = sync.Mutex{}

// engineInfo contains all the necessary information about DNS engines configuration.
// we use it to periodically reload DNS engines.
type engineInfo struct {
	filtersPaths []string
	dnsEngine    *urlfilter.DNSEngine

	data *safeservices.SafeService
}

// getSafeBrowsingEngine returns the safebrowsing filtering engineInfo
func (p *plug) getSafeBrowsingEngine() *engineInfo {
	enginesMapGuard.Lock()
	e, ok := enginesMap[p.settings.SafeBrowsingFilterPath]
	enginesMapGuard.Unlock()
	if ok {
		return e
	}

	return nil
}

// getParentalEngine returns the parental filtering engineInfo
func (p *plug) getParentalEngine() *engineInfo {
	enginesMapGuard.Lock()
	e, ok := enginesMap[p.settings.ParentalFilterPath]
	enginesMapGuard.Unlock()
	if ok {
		return e
	}

	return nil
}

// getBlockingEngines returns the list of blocking engines
func (p *plug) getBlockingEngine() *urlfilter.DNSEngine {
	enginesMapGuard.Lock()
	e, ok := enginesMap[p.settings.filterPathsKey]
	enginesMapGuard.Unlock()
	if ok {
		return e.dnsEngine
	}

	return nil
}

func engineExists(key string) bool {
	enginesMapGuard.Lock()
	_, ok := enginesMap[key]
	enginesMapGuard.Unlock()
	return ok
}
