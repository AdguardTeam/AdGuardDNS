package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
)

func TestServer_SetBindConfigs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		wantPanicMsg string
		in           agdnet.BindConfigs
	}{{
		name:         "nil",
		wantPanicMsg: "bind config: " + errors.ErrEmptyValue.Error(),
		in:           nil,
	}, {
		name:         "empty",
		wantPanicMsg: "bind config: " + errors.ErrEmptyValue.Error(),
		in:           agdnet.BindConfigs{},
	}, {
		name:         "one",
		wantPanicMsg: "",
		in:           agdnet.BindConfigs{agdtest.BindConfigV4},
	}, {
		name:         "two_same_type",
		wantPanicMsg: "",
		in: agdnet.BindConfigs{
			agdtest.BindConfigV4,
			agdtest.BindConfigV6,
		},
	}, {
		name: "two_diff_type",
		wantPanicMsg: "setting bind configs: at index 1:" +
			" inconsistent type of bind config address: *agdnet.BindConfigAddrPrefix",
		in: agdnet.BindConfigs{
			agdtest.BindConfigV4,
			agdtest.BindConfigIfaceV4,
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := func() {
				s := &agd.Server{}
				s.SetBindConfigs(tc.in)

				assert.NotEmpty(t, s.BindConfigs())
			}

			if tc.wantPanicMsg == "" {
				assert.NotPanics(t, f)
			} else {
				assert.PanicsWithError(t, tc.wantPanicMsg, f)
			}
		})
	}
}

func TestServer_BindsToInterfaces(t *testing.T) {
	t.Parallel()

	s := &agd.Server{}
	assert.False(t, s.BindsToInterfaces())

	s.SetBindConfigs(agdnet.BindConfigs{agdtest.BindConfigV4})
	assert.False(t, s.BindsToInterfaces())

	s.SetBindConfigs(agdnet.BindConfigs{agdtest.BindConfigIfaceV4})
	assert.True(t, s.BindsToInterfaces())

	s.SetBindConfigs(agdnet.BindConfigs{agdtest.BindConfigIfaceV4SingleIP})
	assert.True(t, s.BindsToInterfaces())
}
