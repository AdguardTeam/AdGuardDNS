package dnsmsg_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
)

// type check
var _ errcoll.SentryReportableError = dnsmsg.BadECSError{}
