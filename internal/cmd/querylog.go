package cmd

import "fmt"

// Query log configuration

// queryLogConfig is the query log configuration.
type queryLogConfig struct {
	// File contains the JSONL file query log configuration.
	File *queryLogFileConfig `yaml:"file"`
}

// validate returns an error if the query log configuration is invalid.
func (c *queryLogConfig) validate() (err error) {
	switch {
	case c == nil:
		return errNilConfig
	case c.File == nil:
		return fmt.Errorf("file: %w", errNilConfig)
	default:
		return nil
	}
}

// queryLogFileConfig is the JSONL file query log configuration.
type queryLogFileConfig struct {
	Enabled bool `yaml:"enabled"`
}
