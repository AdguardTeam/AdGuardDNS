package dnspb

import (
	"context"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
)

// ToStandardConfig converts protobuf access settings to an internal structure.
// If x is nil, toStandardConfig returns nil.  l and errColl must not be nil.
func (x *AccessSettings) ToStandardConfig(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
) (a *access.StandardBlockerConfig) {
	if !x.GetEnabled() {
		l.WarnContext(ctx, "received disabled standard access settings")

		return nil
	}

	return &access.StandardBlockerConfig{
		AllowedNets:          CIDRRangeToInternal(ctx, l, x.AllowlistCidr, errColl),
		BlockedNets:          CIDRRangeToInternal(ctx, l, x.BlocklistCidr, errColl),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
	}
}

// toInternal converts protobuf access settings to an internal structure.  If x
// is nil, toInternal returns [access.EmptyProfile].   l, errColl, and cons must
// not be nil.
func (x *AccessSettings) toInternal(
	ctx context.Context,
	l *slog.Logger,
	errColl errcoll.Interface,
	cons *access.ProfileConstructor,
	standardEnabled bool,
) (a access.Profile) {
	if !x.GetEnabled() {
		return access.EmptyProfile{}
	}

	return cons.New(&access.ProfileConfig{
		AllowedNets:          CIDRRangeToInternal(ctx, l, x.AllowlistCidr, errColl),
		BlockedNets:          CIDRRangeToInternal(ctx, l, x.BlocklistCidr, errColl),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
		StandardEnabled:      standardEnabled,
	})
}

// asnToInternal is a helper that converts a slice of ASNs to the slice of
// [geoip.ASN].
func asnToInternal(asns []uint32) (out []geoip.ASN) {
	for _, asn := range asns {
		out = append(out, geoip.ASN(asn))
	}

	return out
}
