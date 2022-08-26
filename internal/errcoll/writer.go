// Package errcoll contains implementations of the agd.ErrorCollector
// interface.
package errcoll

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Simple Writer Collector

// WriterErrorCollector is an agd.ErrorCollector that writes errors to a file.
type WriterErrorCollector struct {
	w io.Writer
}

// NewWriterErrorCollector returns a new WriterErrorCollector.
func NewWriterErrorCollector(w io.Writer) (c *WriterErrorCollector) {
	return &WriterErrorCollector{
		w: w,
	}
}

// Collect implements the agd.ErrorCollector interface for
// *WriterErrorCollector.
func (c *WriterErrorCollector) Collect(ctx context.Context, err error) {
	_, _ = fmt.Fprintf(c.w, "%s: %s: caught error: %s\n", time.Now(), caller(2), err)
}
