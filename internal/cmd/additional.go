package cmd

import (
	"fmt"
	"maps"
	"slices"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/prometheus/common/model"
)

// additionalInfo is a extra info configuration.
type additionalInfo map[string]string

// type check
var _ validate.Interface = additionalInfo(nil)

// Validate implements the [validate.Interface] interface for additionalInfo.
func (c additionalInfo) Validate() (err error) {
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(c)) {
		if !model.LegacyValidation.IsValidLabelName(k) {
			errs = append(errs, fmt.Errorf(
				"prometheus labels must match %s, got %q",
				model.LabelNameRE,
				k,
			))
		}
	}

	return errors.Join(errs...)
}
