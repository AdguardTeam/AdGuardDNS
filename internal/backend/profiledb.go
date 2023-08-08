package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"golang.org/x/exp/slices"
)

// Profile Storage

// ProfileStorageConfig is the configuration for the business logic backend
// profile storage.
type ProfileStorageConfig struct {
	// BaseEntpoint is the base URL to which API paths are appended.
	BaseEndpoint *url.URL

	// Now is returns the current time, typically time.Now.  It is used to set
	// UpdateTime on profiles.
	Now func() (t time.Time)

	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.
	ErrColl agd.ErrorCollector
}

// NewProfileStorage returns a new [ProfileStorage] that retrieves information
// from the business logic backend.
func NewProfileStorage(c *ProfileStorageConfig) (s *ProfileStorage) {
	return &ProfileStorage{
		apiURL: c.BaseEndpoint.JoinPath(PathDNSAPIV1Settings),
		// Assume that the timeouts are handled by the context in Profiles.
		http:    agdhttp.NewClient(&agdhttp.ClientConfig{}),
		now:     c.Now,
		errColl: c.ErrColl,
	}
}

// ProfileStorage is the implementation of the [profiledb.Storage] interface
// that retrieves the profile and device information from the business logic
// backend.  It is safe for concurrent use.
//
// TODO(a.garipov): Consider uniting with [BillStat] into a single
// backend.Client.
type ProfileStorage struct {
	apiURL  *url.URL
	http    *agdhttp.Client
	now     func() (t time.Time)
	errColl agd.ErrorCollector
}

// type check
var _ profiledb.Storage = (*ProfileStorage)(nil)

// Profiles implements the [profiledb.Storage] interface for *ProfileStorage.
func (s *ProfileStorage) Profiles(
	ctx context.Context,
	req *profiledb.StorageRequest,
) (resp *profiledb.StorageResponse, err error) {
	q := url.Values{}
	if !req.SyncTime.IsZero() {
		syncTimeStr := strconv.FormatInt(req.SyncTime.UnixMilli(), 10)
		q.Add("sync_time", syncTimeStr)
	}

	u := netutil.CloneURL(s.apiURL)
	u.RawQuery = q.Encode()
	redURL := u.Redacted()

	settResp, err := s.loadSettingsResponse(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("loading from url %s: %w", redURL, err)
	}

	return settResp.toInternal(ctx, s.now(), s.errColl), nil
}

// loadSettingsResponse fetches, decodes, and returns the settings response.
func (s *ProfileStorage) loadSettingsResponse(
	ctx context.Context,
	u *url.URL,
) (resp *v1SettingsResp, err error) {
	httpResp, err := s.http.Get(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("calling backend: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	err = agdhttp.CheckStatus(httpResp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	resp = &v1SettingsResp{}
	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, agdhttp.WrapServerError(
			fmt.Errorf("decoding response: %w", err),
			httpResp,
		)
	}

	return resp, nil
}

// v1SettingsRespSchedule is the structure for decoding the
// settings.*.parental.schedule property of the response from the backend.
type v1SettingsRespSchedule struct {
	// TODO(a.garipov): Consider making a custom type detecting an absence of
	// value to remove these pointers.
	Monday    *[2]timeutil.Duration `json:"mon"`
	Tuesday   *[2]timeutil.Duration `json:"tue"`
	Wednesday *[2]timeutil.Duration `json:"wed"`
	Thursday  *[2]timeutil.Duration `json:"thu"`
	Friday    *[2]timeutil.Duration `json:"fri"`
	Saturday  *[2]timeutil.Duration `json:"sat"`
	Sunday    *[2]timeutil.Duration `json:"sun"`

	// TimeZone is the tzdata name of the time zone.
	//
	// NOTE: Do not use *agdtime.Location here so that lookup failures are
	// properly mitigated in [v1SettingsRespParental.toInternal].
	TimeZone string `json:"tmz"`
}

// v1SettingsRespParental is the structure for decoding the settings.*.parental
// property of the response from the backend.
type v1SettingsRespParental struct {
	Schedule *v1SettingsRespSchedule `json:"schedule"`

	BlockedServices []string `json:"blocked_services"`

	Enabled           bool `json:"enabled"`
	BlockAdult        bool `json:"block_adult"`
	GeneralSafeSearch bool `json:"general_safe_search"`
	YoutubeSafeSearch bool `json:"youtube_safe_search"`
}

// v1SettingsRespDevice is the structure for decoding the settings.devices
// property of the response from the backend.
type v1SettingsRespDevice struct {
	LinkedIP         netip.Addr   `json:"linked_ip"`
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	DedicatedIPs     []netip.Addr `json:"dedicated_ips"`
	FilteringEnabled bool         `json:"filtering_enabled"`
}

// v1SettingsRespSettings is the structure for decoding the settings property of
// the response from the backend.
type v1SettingsRespSettings struct {
	DNSID               string                      `json:"dns_id"`
	Parental            *v1SettingsRespParental     `json:"parental"`
	RuleLists           *v1SettingsRespRuleLists    `json:"rule_lists"`
	SafeBrowsing        *v1SettingsRespSafeBrowsing `json:"safe_browsing"`
	BlockingMode        dnsmsg.BlockingModeCodec    `json:"blocking_mode"`
	Devices             []*v1SettingsRespDevice     `json:"devices"`
	CustomRules         []string                    `json:"custom_rules"`
	FilteredResponseTTL uint32                      `json:"filtered_response_ttl"`
	QueryLogEnabled     bool                        `json:"query_log_enabled"`
	FilteringEnabled    bool                        `json:"filtering_enabled"`
	Deleted             bool                        `json:"deleted"`
	BlockPrivateRelay   bool                        `json:"block_private_relay"`
	BlockFirefoxCanary  bool                        `json:"block_firefox_canary"`
}

// type check
var _ json.Unmarshaler = (*v1SettingsRespSettings)(nil)

// UnmarshalJSON implements the [json.Unmarshaler] interface for
// *v1SettingsRespSettings.  It puts default value into BlockFirefoxCanary
// field while it is not implemented on the backend side.
//
// TODO(a.garipov): Remove once the backend starts to always send it.
func (rs *v1SettingsRespSettings) UnmarshalJSON(b []byte) (err error) {
	type defaultDec v1SettingsRespSettings

	s := defaultDec{
		BlockingMode: dnsmsg.BlockingModeCodec{
			Mode: &dnsmsg.BlockingModeNullIP{},
		},
		BlockFirefoxCanary: true,
	}

	if err = json.Unmarshal(b, &s); err != nil {
		return err
	}

	*rs = v1SettingsRespSettings(s)

	return nil
}

// v1SettingsRespRuleLists is the structure for decoding filtering rule lists
// based filtering settings from the backend.
type v1SettingsRespRuleLists struct {
	IDs     []string `json:"ids"`
	Enabled bool     `json:"enabled"`
}

// v1SettingsRespSafeBrowsing is the structure for decoding the general safe
// browsing filtering settings from the backend.
type v1SettingsRespSafeBrowsing struct {
	BlockDangerousDomains       *bool `json:"block_dangerous_domains"`
	BlockNewlyRegisteredDomains bool  `json:"block_nrd"`
	Enabled                     bool  `json:"enabled"`
}

// toInternal converts s to an [agd.SafeBrowsingSettings] instance.
func (s *v1SettingsRespSafeBrowsing) toInternal() (res *agd.SafeBrowsingSettings) {
	if s == nil {
		return nil
	}

	// TODO(d.kolyshev): Don't make this migration after AGDNS-1537.
	blockDangerDomains := s.Enabled
	if s.BlockDangerousDomains != nil {
		blockDangerDomains = *s.BlockDangerousDomains
	}

	return &agd.SafeBrowsingSettings{
		Enabled:                     s.Enabled,
		BlockDangerousDomains:       blockDangerDomains,
		BlockNewlyRegisteredDomains: s.BlockNewlyRegisteredDomains,
	}
}

// v1SettingsResp is the structure for decoding the response from the backend.
type v1SettingsResp struct {
	Settings []*v1SettingsRespSettings `json:"settings"`

	SyncTime int64 `json:"sync_time"`
}

// toInternal converts p to an [agd.ParentalProtectionSettings] instance.
func (p *v1SettingsRespParental) toInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
	settIdx int,
) (res *agd.ParentalProtectionSettings, err error) {
	if p == nil {
		return nil, nil
	}

	var sch *agd.ParentalProtectionSchedule
	if psch := p.Schedule; psch != nil {
		sch = &agd.ParentalProtectionSchedule{}

		// TODO(a.garipov): Cache location lookup results.
		sch.TimeZone, err = agdtime.LoadLocation(psch.TimeZone)
		if err != nil {
			// Report the error and assume UTC.
			reportf(ctx, errColl, "settings at index %d: schedule: time zone: %w", settIdx, err)

			sch.TimeZone = agdtime.UTC()
		}

		sch.Week = &agd.WeeklySchedule{}
		days := []*[2]timeutil.Duration{
			psch.Sunday,
			psch.Monday,
			psch.Tuesday,
			psch.Wednesday,
			psch.Thursday,
			psch.Friday,
			psch.Saturday,
		}
		for i, d := range days {
			if d == nil {
				sch.Week[i] = agd.ZeroLengthDayRange()

				continue
			}

			sch.Week[i] = agd.DayRange{
				Start: uint16(d[0].Minutes()),
				End:   uint16(d[1].Minutes()),
			}
		}

		for i, r := range sch.Week {
			err = r.Validate()
			if err != nil {
				return nil, fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
			}
		}
	}

	blockedSvcs := blockedSvcsToInternal(ctx, errColl, settIdx, p.BlockedServices)

	return &agd.ParentalProtectionSettings{
		Schedule: sch,

		BlockedServices: blockedSvcs,

		Enabled:           p.Enabled,
		BlockAdult:        p.BlockAdult,
		GeneralSafeSearch: p.GeneralSafeSearch,
		YoutubeSafeSearch: p.YoutubeSafeSearch,
	}, nil
}

// blockedSvcsToInternal is a helper that converts the blocked service IDs from
// the backend response to AdGuard DNS blocked service IDs.
func blockedSvcsToInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
	settIdx int,
	respSvcs []string,
) (svcs []agd.BlockedServiceID) {
	l := len(respSvcs)
	if l == 0 {
		return nil
	}

	svcs = make([]agd.BlockedServiceID, 0, l)
	for i, s := range respSvcs {
		id, err := agd.NewBlockedServiceID(s)
		if err != nil {
			reportf(
				ctx,
				errColl,
				"settings at index %d: blocked service at index %d: %w",
				settIdx,
				i,
				err,
			)

			continue
		}

		svcs = append(svcs, id)
	}

	return svcs
}

// settsRespPrefix is the logging prefix for logs by v1SettingsResp.
const settsRespPrefix = "backend.v1SettingsResp"

// devicesToInternal is a helper that converts the devices from the backend
// response to AdGuard DNS devices.
func devicesToInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
	settIdx int,
	respDevices []*v1SettingsRespDevice,
) (devices []*agd.Device, ids []agd.DeviceID) {
	l := len(respDevices)
	if l == 0 {
		return nil, nil
	}

	devices = make([]*agd.Device, 0, l)
	for i, d := range respDevices {
		if d == nil {
			reportf(ctx, errColl, "settings at index %d: device at index %d: is nil", settIdx, i)

			continue
		}

		// TODO(a.garipov): Consider validating uniqueness of linked and
		// dedicated IPs.
		dev := &agd.Device{
			LinkedIP:         d.LinkedIP,
			DedicatedIPs:     slices.Clone(d.DedicatedIPs),
			FilteringEnabled: d.FilteringEnabled,
		}

		// Use the same error message format string from now on, since all
		// constructors and validators return informative errors.
		const msgFmt = "settings at index %d: device at index %d: %w"

		var err error
		dev.ID, err = agd.NewDeviceID(d.ID)
		if err != nil {
			reportf(ctx, errColl, msgFmt, settIdx, i, err)

			continue
		}

		dev.Name, err = agd.NewDeviceName(d.Name)
		if err != nil {
			reportf(ctx, errColl, msgFmt, settIdx, i, err)

			continue
		}

		ids = append(ids, dev.ID)
		devices = append(devices, dev)
	}

	return devices, ids
}

// filterListsToInternal is a helper that converts the filter lists from the
// backend response to AdGuard DNS devices.
func filterListsToInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
	settIdx int,
	respFilters *v1SettingsRespRuleLists,
) (enabled bool, filterLists []agd.FilterListID) {
	if respFilters == nil {
		return false, nil
	}

	lists := respFilters.IDs
	l := len(lists)
	if l == 0 {
		return respFilters.Enabled, nil
	}

	filterLists = make([]agd.FilterListID, 0, l)
	for i, f := range lists {
		id, err := agd.NewFilterListID(f)
		if err != nil {
			reportf(ctx, errColl, "settings at index %d: filter at index %d: %w", settIdx, i, err)

			continue
		}

		filterLists = append(filterLists, id)
	}

	return respFilters.Enabled, filterLists
}

// rulesToInternal is a helper that converts the filter rules from the backend
// response to AdGuard DNS filtering rules.
func rulesToInternal(
	ctx context.Context,
	errColl agd.ErrorCollector,
	settIdx int,
	respRules []string,
) (rules []agd.FilterRuleText) {
	l := len(respRules)
	if l == 0 {
		return nil
	}

	rules = make([]agd.FilterRuleText, 0, l)
	for i, r := range respRules {
		text, err := agd.NewFilterRuleText(r)
		if err != nil {
			reportf(ctx, errColl, "settings at index %d: rule at index %d: %w", settIdx, i, err)

			continue
		}

		rules = append(rules, text)
	}

	return rules
}

// maxFltRespTTL is the maximum allowed filtered response TTL.
const maxFltRespTTL = 1 * time.Hour

// fltRespTTLToInternal converts respTTL to the filtered response TTL.  If
// respTTL is invalid, it returns an error describing the validation error as
// well as the closest valid value to use.
func fltRespTTLToInternal(respTTL uint32) (ttl time.Duration, err error) {
	ttl = time.Duration(respTTL) * time.Second
	if ttl > maxFltRespTTL {
		ttl = maxFltRespTTL
		err = fmt.Errorf("too high: got %s, max %s", ttl, maxFltRespTTL)
	}

	return ttl, err
}

// toInternal converts r to an [agd.DSProfilesResponse] instance.
func (r *v1SettingsResp) toInternal(
	ctx context.Context,
	updTime time.Time,
	// TODO(a.garipov): Here and in other functions, consider just adding the
	// error collector to the context.
	errColl agd.ErrorCollector,
) (pr *profiledb.StorageResponse) {
	if r == nil {
		return nil
	}

	pr = &profiledb.StorageResponse{
		SyncTime: time.Unix(0, r.SyncTime*1_000_000),
		Profiles: make([]*agd.Profile, 0, len(r.Settings)),
	}

	for i, s := range r.Settings {
		parental, err := s.Parental.toInternal(ctx, errColl, i)
		if err != nil {
			reportf(ctx, errColl, "settings at index %d: parental: %w", i, err)

			continue
		}

		devices, deviceIDs := devicesToInternal(ctx, errColl, i, s.Devices)
		rlEnabled, ruleLists := filterListsToInternal(ctx, errColl, i, s.RuleLists)
		rules := rulesToInternal(ctx, errColl, i, s.CustomRules)

		id, err := agd.NewProfileID(s.DNSID)
		if err != nil {
			reportf(ctx, errColl, "settings at index %d: profile id: %w", i, err)

			continue
		}

		fltRespTTL, err := fltRespTTLToInternal(s.FilteredResponseTTL)
		if err != nil {
			reportf(ctx, errColl, "settings at index %d: filtered resp ttl: %w", i, err)

			// Go on and use the fixed value.
			//
			// TODO(ameshkov, a.garipov): Consider continuing, like with all
			// other validation errors.
		}

		pr.Devices = append(pr.Devices, devices...)

		pr.Profiles = append(pr.Profiles, &agd.Profile{
			Parental:            parental,
			BlockingMode:        s.BlockingMode,
			ID:                  id,
			UpdateTime:          updTime,
			DeviceIDs:           deviceIDs,
			RuleListIDs:         ruleLists,
			CustomRules:         rules,
			FilteredResponseTTL: fltRespTTL,
			SafeBrowsing:        s.SafeBrowsing.toInternal(),
			RuleListsEnabled:    rlEnabled,
			FilteringEnabled:    s.FilteringEnabled,
			QueryLogEnabled:     s.QueryLogEnabled,
			Deleted:             s.Deleted,
			BlockPrivateRelay:   s.BlockPrivateRelay,
			BlockFirefoxCanary:  s.BlockFirefoxCanary,
		})
	}

	return pr
}

// reportf is a helper method for reporting non-critical errors.
func reportf(ctx context.Context, errColl agd.ErrorCollector, format string, args ...any) {
	agd.Collectf(ctx, errColl, settsRespPrefix+": "+format, args...)
}
