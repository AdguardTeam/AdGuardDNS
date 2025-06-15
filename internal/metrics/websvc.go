package metrics

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// WebSvcReqType is a type alias for a string that represents the web service
// request type.
type WebSvcReqType = string

// Web service requests of [WebSvcReqType] type.
//
// NOTE:  Keep in sync with [websvc.RequestType].
const (
	WebSvcReqTypeError404            WebSvcReqType = "error404"
	WebSvcReqTypeError500            WebSvcReqType = "error500"
	WebSvcReqTypeStaticContent       WebSvcReqType = "static_content"
	WebSvcReqTypeDNSCheckTest        WebSvcReqType = "dnscheck_test"
	WebSvcReqTypeRobotsTxt           WebSvcReqType = "robots_txt"
	WebSvcReqTypeRootRedirect        WebSvcReqType = "root_redirect"
	WebSvcReqTypeLinkedIPProxy       WebSvcReqType = "linkip"
	WebSvcReqTypeAdultBlockingPage   WebSvcReqType = "adult_blocking_page"
	WebSvcReqTypeGeneralBlockingPage WebSvcReqType = "general_blocking_page"
	WebSvcReqTypeSafeBrowsingPage    WebSvcReqType = "safe_browsing_page"
)

// WebSvc is the Prometheus-based implementation of the [websvc.Metrics]
// interface.
type WebSvc struct {
	// webSvcReqCounters maps each web service request type to its corresponding
	// Prometheus counter.
	webSvcReqCounters map[WebSvcReqType]prometheus.Counter
}

// NewWebSvc registers the web service metrics in reg and returns a properly
// initialized [*WebSvc].
func NewWebSvc(namespace string, reg prometheus.Registerer) (m *WebSvc, err error) {
	// TODO(s.chzhen):  Rename this to avoid sharing a prefix with
	// [subsystemWebSvc].
	const webSvcReqTotal = "websvc_requests_total"

	// reqCV is a Prometheus counter vector that tracks the number of web
	// service requests, categorized by request type.
	reqCV := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      webSvcReqTotal,
		Namespace: namespace,
		Subsystem: subsystemWebSvc,
		Help:      "The number of HTTP requests for websvc.",
	}, []string{"kind"})

	webSvcReqCounters := map[WebSvcReqType]prometheus.Counter{
		WebSvcReqTypeError404:            reqCV.WithLabelValues(WebSvcReqTypeError404),
		WebSvcReqTypeError500:            reqCV.WithLabelValues(WebSvcReqTypeError500),
		WebSvcReqTypeStaticContent:       reqCV.WithLabelValues(WebSvcReqTypeStaticContent),
		WebSvcReqTypeDNSCheckTest:        reqCV.WithLabelValues(WebSvcReqTypeDNSCheckTest),
		WebSvcReqTypeRobotsTxt:           reqCV.WithLabelValues(WebSvcReqTypeRobotsTxt),
		WebSvcReqTypeRootRedirect:        reqCV.WithLabelValues(WebSvcReqTypeRootRedirect),
		WebSvcReqTypeLinkedIPProxy:       reqCV.WithLabelValues(WebSvcReqTypeLinkedIPProxy),
		WebSvcReqTypeAdultBlockingPage:   reqCV.WithLabelValues(WebSvcReqTypeAdultBlockingPage),
		WebSvcReqTypeGeneralBlockingPage: reqCV.WithLabelValues(WebSvcReqTypeGeneralBlockingPage),
		WebSvcReqTypeSafeBrowsingPage:    reqCV.WithLabelValues(WebSvcReqTypeSafeBrowsingPage),
	}

	err = reg.Register(reqCV)
	if err != nil {
		return nil, fmt.Errorf("registering metrics %q: %w", webSvcReqTotal, err)
	}

	return &WebSvc{webSvcReqCounters: webSvcReqCounters}, nil
}

// IncrementReqCount implements the [websvc.Metrics] interface for *WebSvc.
func (m *WebSvc) IncrementReqCount(_ context.Context, reqType WebSvcReqType) {
	ctr, ok := m.webSvcReqCounters[reqType]
	if !ok {
		panic(fmt.Errorf("incrementing req counter: bad type %q", reqType))
	}

	ctr.Inc()
}
