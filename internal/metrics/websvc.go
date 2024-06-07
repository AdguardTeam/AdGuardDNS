package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	webSvcRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "websvc_requests_total",
		Namespace: namespace,
		Subsystem: subsystemWebSvc,
		Help:      "The number of HTTP requests for websvc.",
	}, []string{"kind"})

	// WebSvcError404RequestsTotal is a counter with total number of
	// requests with error 404.
	WebSvcError404RequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "error404",
	})

	// WebSvcError500RequestsTotal is a counter with total number of
	// requests with error 500.
	WebSvcError500RequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "error500",
	})

	// WebSvcStaticContentRequestsTotal is a counter with total number of
	// requests for static content.
	WebSvcStaticContentRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "static_content",
	})

	// WebSvcDNSCheckTestRequestsTotal is a counter with total number of
	// requests for dnscheck_test.
	WebSvcDNSCheckTestRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "dnscheck_test",
	})

	// WebSvcRobotsTxtRequestsTotal is a counter with total number of
	// requests for robots_txt.
	WebSvcRobotsTxtRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "robots_txt",
	})

	// WebSvcRootRedirectRequestsTotal is a counter with total number of
	// root redirected requests.
	WebSvcRootRedirectRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "root_redirect",
	})

	// WebSvcLinkedIPProxyRequestsTotal is a counter with total number of
	// requests with linked ip.
	WebSvcLinkedIPProxyRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "linkip",
	})

	// WebSvcAdultBlockingPageRequestsTotal is a counter with total number
	// of requests for adult blocking page.
	WebSvcAdultBlockingPageRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "adult_blocking_page",
	})

	// WebSvcGeneralBlockingPageRequestsTotal is a counter with total number
	// of requests for general blocking page.
	WebSvcGeneralBlockingPageRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "general_blocking_page",
	})

	// WebSvcSafeBrowsingPageRequestsTotal is a counter with total number
	// of requests for safe browsing page.
	WebSvcSafeBrowsingPageRequestsTotal = webSvcRequestsTotal.With(prometheus.Labels{
		"kind": "safe_browsing_page",
	})
)
