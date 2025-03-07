package cmd

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// queryLogConfig is the query log configuration.
type queryLogConfig struct {
	// File contains the JSONL file query log configuration.
	File *queryLogFileConfig `yaml:"file"`
}

// type check
var _ validate.Interface = (*queryLogConfig)(nil)

// Validate implements the [validate.Interface] interface for *queryLogConfig.
func (c *queryLogConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	return validate.NotNil("file", c.File)
}

// queryLogFileConfig is the JSONL file query log configuration.
type queryLogFileConfig struct {
	Enabled bool `yaml:"enabled"`
}
