package dnsfilter

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

// don't allow too small files
const minFileSize = 1024

type updateInfo struct {
	path            string        // path to the filter list file
	url             string        // url to load filter list from
	ttl             time.Duration // update check period
	lastTimeUpdated time.Time     // last update we tried to check updates
}

// update does the update if necessary
// returns true if update was performed, otherwise - false
func (u *updateInfo) update() (bool, error) {
	shouldUpdate := false

	if _, err := os.Stat(u.path); os.IsNotExist(err) {
		clog.Infof("File %s does not exist, we should download the filter list", u.path)
		shouldUpdate = true
	} else if u.lastTimeUpdated.Add(u.ttl).Before(time.Now()) {
		clog.Infof("Time to download updates for %s", u.path)
		shouldUpdate = true
	}

	if shouldUpdate {
		err := u.download()
		u.lastTimeUpdated = time.Now()
		return err == nil, err
	}

	return false, nil
}

// download downloads the file from URL and replaces it in the path
func (u *updateInfo) download() error {
	clog.Infof("Downloading filter %s", u.path)

	client := new(http.Client)

	request, err := http.NewRequest("GET", u.url, nil)
	if err != nil {
		return err
	}

	request.Header.Add("Accept-Encoding", "gzip")

	// Make the request
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download %s, response status is %d", u.url, response.StatusCode)
	}

	// Check that the server actually sent compressed data
	var reader io.ReadCloser
	switch response.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(response.Body)
		if err != nil {
			return err
		}
	default:
		reader = response.Body
	}
	defer func() { _ = reader.Close() }()

	// Start reading the response to a temp file
	tmpFilePath := u.path + ".tmp"
	tmpFile, err := os.OpenFile(tmpFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFilePath)
	}()
	if err != nil {
		return err
	}

	// Write the content to that file
	// nolint (gosec)
	written, err := io.Copy(tmpFile, reader)
	if err != nil {
		return err
	}

	if written < minFileSize {
		return fmt.Errorf("the file downloaded from %s is too small: %d", u.url, written)
	}

	clog.Infof("Downloaded update for %s, size=%d", u.path, written)

	// Now replace the file
	_ = tmpFile.Close()
	return os.Rename(tmpFilePath, u.path)
}
