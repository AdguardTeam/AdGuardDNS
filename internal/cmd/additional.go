package cmd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/mapsutil"
	"github.com/prometheus/common/model"
)

// Additional prometheus information configuration

// additionalInfo is a extra info configuration.
type additionalInfo map[string]string

// validateAdditionalInfo return an error is the section is invalid.
func (c additionalInfo) validate() (err error) {
	return mapsutil.OrderedRangeError(c, func(k, _ string) (keyErr error) {
		if model.LabelName(k).IsValid() {
			return nil
		}

		return fmt.Errorf("prometheus labels must match %s, got %q", model.LabelNameRE, k)
	})
}
