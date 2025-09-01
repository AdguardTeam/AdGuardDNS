package custom_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilter(t *testing.T) {
	t.Parallel()

	rules := []filter.RuleText{
		filtertest.RuleBlock,
		filtertest.RuleBlockForClientIP,
		filtertest.RuleBlockForClientName,
	}

	f := custom.New(&custom.Config{
		Logger: slogutil.NewDiscardLogger(),
		Rules:  rules,
	})
	require.NotNil(t, f)
	require.Equal(t, rules, f.Rules())

	ctx := context.Background()

	testCases := []struct {
		name        string
		cliName     string
		host        string
		wantRuleStr string
	}{{
		name:        "simple",
		cliName:     "",
		host:        filtertest.HostBlocked,
		wantRuleStr: filtertest.RuleBlockStr,
	}, {
		name:        "client_ip",
		cliName:     "",
		host:        filtertest.HostBlockedForClientIP,
		wantRuleStr: filtertest.RuleBlockForClientIPStr,
	}, {
		name:        "client_name",
		cliName:     filtertest.ClientName,
		host:        filtertest.HostBlockedForClientName,
		wantRuleStr: filtertest.RuleBlockForClientNameStr,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := &urlfilter.DNSRequest{
				ClientIP:   filtertest.IPv4Client,
				ClientName: tc.cliName,
				Hostname:   tc.host,
				DNSType:    dns.TypeA,
			}
			res := &urlfilter.DNSResult{}

			ok := f.SetURLFilterResult(ctx, req, res)

			require.True(t, ok)
			require.NotNil(t, res.NetworkRule)

			assert.Equal(t, tc.wantRuleStr, res.NetworkRule.RuleText)
		})
	}
}
