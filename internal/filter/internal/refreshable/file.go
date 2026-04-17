package refreshable

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/AdguardTeam/golibs/errors"
)

// DataFromFile loads data from filePath if the file's mtime shows that it's
// still fresh relative to updTime.  If acceptStale is true, and the file
// exists, the data is read from there regardless of its staleness.
//
// TODO(a.garipov):  Add [os.Root] support and/or use [io.Reader]s.
func DataFromFile(
	filePath string,
	updTime time.Time,
	staleness time.Duration,
	acceptStale bool,
) (b []byte, err error) {
	// #nosec G304 -- Assume that filePath is always either cacheDir + a valid,
	// no-slash ID or a path from the index env.
	file, err := os.Open(filePath)
	if errors.Is(err, os.ErrNotExist) {
		// File does not exist.  Refresh from network.
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("opening refreshable file: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, file.Close()) }()

	if !acceptStale {
		var fi fs.FileInfo
		fi, err = file.Stat()
		if err != nil {
			return nil, fmt.Errorf("reading refreshable file stat: %w", err)
		}

		if mtime := fi.ModTime(); !mtime.Add(staleness).After(updTime) {
			return nil, nil
		}
	}

	// Consider cache files to be of a prevalidated size.
	b, err = io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("reading refreshable file: %w", err)
	}

	return b, nil
}
