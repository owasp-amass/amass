// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics/cloudranges"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const awsFeed = `{
	"prefixes": [
		{"ip_prefix": "52.95.0.0/16", "region": "us-east-1", "service": "S3"},
		{"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"}
	]
}`

func testPlugin() *plugin {
	p := NewCloudRanges().(*plugin)
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return p
}

// TestEnsureMatcherStubbedFeeds builds the matcher from a stubbed fetch that
// serves one provider and fails the rest, and checks the failed feeds are
// skipped, the served ranges match, and the matcher is cached within its TTL.
func TestEnsureMatcherStubbedFeeds(t *testing.T) {
	sess := plugintest.NewSession(t)
	p := testPlugin()

	var fetches int
	p.fetch = func(_ context.Context, _ et.Session, url string) ([]byte, error) {
		fetches++
		if url == "https://ip-ranges.amazonaws.com/ip-ranges.json" {
			return []byte(awsFeed), nil
		}
		return nil, errors.New("unreachable in test")
	}

	m, err := p.ensureMatcher(sess)
	require.NoError(t, err)

	// Every catalog feed was attempted once.
	feedCount := 0
	for _, pr := range cloudranges.Providers() {
		feedCount += len(pr.Feeds)
	}
	assert.Equal(t, feedCount, fetches, "every feed should be fetched once on a cold build")

	match, ok := m.Match(netip.MustParseAddr("52.95.4.5"))
	require.True(t, ok, "an AWS address was not matched")
	assert.Equal(t, "Amazon Web Services", match.Organization)
	assert.Equal(t, "us-east-1", match.Region)
	assert.Equal(t, "S3", match.Service)

	// An address in no served range is unattributed (the other feeds failed).
	_, ok = m.Match(netip.MustParseAddr("8.8.8.8"))
	assert.False(t, ok)

	// A second build within the TTL reuses the cached matcher: no new fetches.
	before := fetches
	_, err = p.ensureMatcher(sess)
	require.NoError(t, err)
	assert.Equal(t, before, fetches, "the matcher should be cached within its TTL")
}

// TestRecordWritesProviderObservation checks that a matched address is
// recorded as the published prefix netblock, a provider Organization on it,
// and the region and service as properties.
func TestRecordWritesProviderObservation(t *testing.T) {
	sess := plugintest.NewSession(t)
	p := testPlugin()

	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("52.95.4.5"), Type: "IPv4"})
	e := &et.Event{Entity: ip, Session: sess, Dispatcher: &plugintest.Dispatcher{}}

	match := cloudranges.Match{
		ProviderKey:  "aws",
		Organization: "Amazon Web Services",
		Region:       "us-east-1",
		Service:      "S3",
		Prefix:       netip.MustParsePrefix("52.95.0.0/16"),
	}
	require.NoError(t, p.record(e, match))

	ctx := context.Background()
	// The published prefix is stored as a netblock.
	nb, err := sess.DB().CreateAsset(ctx, &oamnet.Netblock{Type: "IPv4", CIDR: match.Prefix})
	require.NoError(t, err)

	// It names the provider Organization through a provider edge.
	edges, err := sess.DB().OutgoingEdges(ctx, nb, time.Time{}, "provider")
	require.NoError(t, err)
	require.Len(t, edges, 1, "expected one provider edge")
	target, err := sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	require.NoError(t, err)
	org, ok := target.Asset.(*oamorg.Organization)
	require.True(t, ok, "the provider edge does not point at an Organization")
	// The asset carries the normalized name (the display form is a name
	// claim), so compare case-insensitively.
	assert.True(t, strings.EqualFold("Amazon Web Services", org.Name),
		"provider org name = %q", org.Name)

	// It contains the matched address.
	contains, err := sess.DB().OutgoingEdges(ctx, nb, time.Time{}, "contains")
	require.NoError(t, err)
	var found bool
	for _, c := range contains {
		if c.ToEntity.ID == ip.ID {
			found = true
		}
	}
	assert.True(t, found, "the netblock does not contain the matched address")

	// The region and service are stored as properties on the netblock.
	region, service := simpleProps(t, sess, nb)
	assert.Equal(t, "us-east-1", region)
	assert.Equal(t, "S3", service)
}

func simpleProps(t *testing.T, sess *plugintest.Session, ent *dbt.Entity) (region, service string) {
	t.Helper()

	tags, err := sess.DB().FindEntityTags(context.Background(), ent, time.Time{})
	require.NoError(t, err)
	for _, tag := range tags {
		sp, ok := tag.Property.(*oamgen.SimpleProperty)
		if !ok {
			continue
		}
		switch sp.PropertyName {
		case propCloudRegion:
			region = sp.PropertyValue
		case propCloudService:
			service = sp.PropertyValue
		}
	}
	return region, service
}

// A name that aliases a provider's name (a CNAME to a CDN host) is hosted at
// the provider's address, so that address is attributed too.
func TestCheckAttributesAddressesBehindAnAlias(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")
	p := testPlugin()
	p.fetch = func(_ context.Context, _ et.Session, url string) ([]byte, error) {
		if url == "https://ip-ranges.amazonaws.com/ip-ranges.json" {
			return []byte(awsFeed), nil
		}
		return nil, errors.New("unreachable in test")
	}

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	edge := sess.Asset(t, &oamdns.FQDN{Name: "d111.cloudfront.net"})
	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("13.32.1.2"), Type: "IPv4"})
	sess.Edge(t, www, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 5, Class: 1}}, edge)
	sess.Edge(t, edge, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}, ip)

	require.NoError(t, p.check(&et.Event{Entity: ip, Session: sess, Dispatcher: &plugintest.Dispatcher{}}))

	nb, err := sess.DB().CreateAsset(context.Background(), &oamnet.Netblock{Type: "IPv4",
		CIDR: netip.MustParsePrefix("13.32.0.0/15")})
	require.NoError(t, err)
	edges, err := sess.DB().OutgoingEdges(context.Background(), nb, time.Time{}, "provider")
	require.NoError(t, err)
	assert.Len(t, edges, 1, "the address behind the alias was not attributed")
}
