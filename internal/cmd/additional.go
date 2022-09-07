package cmd

import (
	"fmt"

	"github.com/prometheus/common/model"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// additionalInfo is a extra info configuration.
type additionalInfo map[string]string

// validateAdditionalInfo return an error is the section is invalid.
func (c additionalInfo) validate() (err error) {
	if c == nil {
		return nil
	}

	keys := maps.Keys(c)
	slices.Sort(keys)

	for _, k := range keys {
		if !model.LabelName(k).IsValid() {
			return fmt.Errorf("prometheus labels must match %s, got %q", model.LabelNameRE, k)
		}
	}

	return nil
}
