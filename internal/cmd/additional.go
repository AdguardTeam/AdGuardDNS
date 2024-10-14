package cmd

import (
	"fmt"
	"maps"
	"slices"

	"github.com/prometheus/common/model"
)

// additionalInfo is a extra info configuration.
type additionalInfo map[string]string

// type check
var _ validator = additionalInfo(nil)

// validate implements the [validator] interface for additionalInfo.
func (c additionalInfo) validate() (err error) {
	for _, k := range slices.Sorted(maps.Keys(c)) {
		if !model.LabelName(k).IsValid() {
			return fmt.Errorf("prometheus labels must match %s, got %q", model.LabelNameRE, k)
		}
	}

	return nil
}
