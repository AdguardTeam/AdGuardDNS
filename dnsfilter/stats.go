package dnsfilter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

// AdGuard Simplified domain names filter list ID
const filterListID = 15
const statsURL = "https://chrome.adtidy.org/api/1.0/rulestats.html"
const uploadPeriod = 10 * time.Minute

type Stats struct {
	FilterLists  map[int]map[string]int `json:"filters"`
	RecordedHits int64                  `json:"-"`
}

var stats = &Stats{
	FilterLists: map[int]map[string]int{},
}
var statsGuard = sync.Mutex{}

func init() {
	go func() {
		for range time.Tick(uploadPeriod) {
			clog.Info("Uploading stats")
			err := uploadStats()
			if err != nil {
				clog.Errorf("error while uploading status: %s", err)
			} else {
				clog.Info("Finished uploading stats successfully")
			}
		}
	}()
}

// recordRuleHit records a new rule hit and increments the stats
func recordRuleHit(ruleText string) {
	statsGuard.Lock()
	defer statsGuard.Unlock()

	v, ok := stats.FilterLists[filterListID]
	if !ok {
		v = map[string]int{}
		stats.FilterLists[filterListID] = v
	}

	hits, ok := v[ruleText]
	if !ok {
		hits = 0
	}
	v[ruleText] = hits + 1
	stats.RecordedHits++
	statsCacheSize.Set(float64(stats.RecordedHits))
}

// uploadStats resets the current stats and sends them to the server
func uploadStats() error {
	statsGuard.Lock()
	statsToUpload := stats
	stats = &Stats{
		FilterLists: map[int]map[string]int{},
	}
	statsGuard.Unlock()
	b, err := json.Marshal(statsToUpload)
	if err != nil {
		statsUploadStatus.Set(0)
		return err
	}

	req, err := http.NewRequest(http.MethodPost, statsURL, bytes.NewReader(b))
	if err != nil {
		statsUploadStatus.Set(0)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		statsUploadStatus.Set(0)
		return err
	}
	_ = resp.Body.Close()

	statsUploadStatus.Set(1)
	statsUploadTimestamp.SetToCurrentTime()
	return nil
}
