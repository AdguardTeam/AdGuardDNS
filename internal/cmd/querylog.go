package cmd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// queryLogConfig is the query log configuration.
type queryLogConfig struct {
	// File contains the JSONL file query log configuration.
	File *queryLogFileConfig `yaml:"file"`
}

// type check
var _ validator = (*queryLogConfig)(nil)

// validate implements the [validator] interface for *queryLogConfig.
func (c *queryLogConfig) validate() (err error) {
	switch {
	case c == nil:
		return errors.ErrNoValue
	case c.File == nil:
		return fmt.Errorf("file: %w", errors.ErrNoValue)
	default:
		return nil
	}
}

// queryLogFileConfig is the JSONL file query log configuration.
type queryLogFileConfig struct {
	Enabled bool `yaml:"enabled"`
}
