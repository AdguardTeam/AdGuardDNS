package dnsfilter

import (
	"sync"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/joomcode/errorx"
)

// updateCheckPeriod is a period that dnsfilter uses to check for filters updates
const updateCheckPeriod = time.Minute * 10

// updatesMap is used to store filter lists update information
// every 10 minutes we're checking if it's time to check for the filter list updates
// if it's time, and if the filter list was successfully updated,
// we reload filtering engines
var updatesMap = make(map[string]*updateInfo)
var updatesMapGuard = sync.Mutex{}

// Start reloading goroutine right away
func init() {
	go reload()
}

func reload() {
	// Wait first time
	time.Sleep(updateCheckPeriod)

	for range time.Tick(updateCheckPeriod) {
		if updateCheck() {
			reloadEngines()
		}
	}
}

// updateCheck - checks and download updates if necessary
// returns true if at least one filter list was updated
func updateCheck() bool {
	wasUpdated := false

	updatesMapGuard.Lock()
	for key, u := range updatesMap {
		updated, err := u.update()
		if err != nil {
			clog.Errorf("Failed to check updates for %s: %v", key, err)
		}
		if updated {
			wasUpdated = true
		}
	}
	updatesMapGuard.Unlock()

	return wasUpdated
}

// reloadEngines reloads all filter lists from the files
func reloadEngines() {
	clog.Info("Start reloading filters")
	enginesMapCopy := make(map[string]*engineInfo)

	enginesMapGuard.Lock()
	for key, engine := range enginesMap {
		enginesMapCopy[key] = engine
	}
	enginesMapGuard.Unlock()

	for key, engine := range enginesMapCopy {
		// TODO: maybe panic would be better here?
		_ = reloadEngine(key, engine)
	}
	clog.Info("Finished reloading filters")
}

// reloadEngine reloads DNS engine and replaces it in the enginesMap
func reloadEngine(key string, engine *engineInfo) error {
	clog.Infof("Reloading filtering engine for %s", key)

	cnt := 0
	var newEngine *engineInfo
	if engine.dnsEngine == nil {
		engine, count, err := createSecurityServiceEngine(key)
		if err != nil {
			return errorx.Decorate(err, "cannot create DNS engine: %s", engine.filtersPaths[0])
		}
		newEngine = engine
		cnt = count
	} else {
		e, count, err := newDNSEngine(engine.filtersPaths)
		if err != nil {
			engineStatus.WithLabelValues(key).Set(float64(0))
			clog.Errorf("failed to reload engine: %s", err)
			return errorx.Decorate(err, "failed to reload engine for %s", key)
		}
		newEngine = &engineInfo{
			dnsEngine:    e,
			filtersPaths: engine.filtersPaths,
		}
		cnt = count
	}

	enginesMapGuard.Lock()
	enginesMap[key] = newEngine
	enginesMapGuard.Unlock()

	engineStatus.WithLabelValues(key).Set(float64(1))
	engineSize.WithLabelValues(key).Set(float64(cnt))
	engineTimestamp.WithLabelValues(key).SetToCurrentTime()
	clog.Infof("Finished reloading filtering engine for %s", key)
	return nil
}
