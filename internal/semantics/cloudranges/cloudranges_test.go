// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cloudranges

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogLoads checks the shipped catalog decodes and that every feed
// names a format this package can parse, so a provider added as data cannot
// reference a parser that does not exist.
func TestCatalogLoads(t *testing.T) {
	providers := Providers()
	require.NotEmpty(t, providers, "the catalog is empty")

	for _, p := range providers {
		assert.NotEmpty(t, p.Key, "a provider has no key")
		assert.NotEmpty(t, p.Organization, "provider %s has no organization", p.Key)
		require.NotEmpty(t, p.Feeds, "provider %s has no feed", p.Key)
		for _, f := range p.Feeds {
			assert.NotEmpty(t, f.URL, "provider %s has a feed with no url", p.Key)
			assert.NotNilf(t, parsers[f.Format], "provider %s feed format %q has no parser", p.Key, f.Format)
		}
	}

	aws, ok := ProviderByKey("aws")
	require.True(t, ok, "aws is not in the catalog")
	assert.Equal(t, "Amazon Web Services", aws.Organization)
}

func TestParseAWS(t *testing.T) {
	data := []byte(`{
		"prefixes": [
			{"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"},
			{"ip_prefix": "52.95.0.0/16", "region": "us-east-1", "service": "EC2"}
		],
		"ipv6_prefixes": [
			{"ipv6_prefix": "2600:9000::/28", "region": "GLOBAL", "service": "CLOUDFRONT"}
		]
	}`)

	got, err := ParseFeed(Feed{Format: "aws", HasRegion: true, HasService: true}, data)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, netip.MustParsePrefix("13.32.0.0/15"), got[0].Prefix)
	assert.Equal(t, "us-east-1", got[1].Region)
	assert.Equal(t, "EC2", got[1].Service)
	assert.True(t, got[2].Prefix.Addr().Is6())
}

func TestParseGCP(t *testing.T) {
	data := []byte(`{"prefixes": [
		{"ipv4Prefix": "34.64.0.0/10", "scope": "asia-northeast3", "service": "Google Cloud"},
		{"ipv6Prefix": "2600:1900::/35", "scope": "us-central1", "service": "Google Cloud"}
	]}`)

	got, err := ParseFeed(Feed{Format: "gcp", HasRegion: true, HasService: true}, data)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "asia-northeast3", got[0].Region)
	assert.Equal(t, netip.MustParsePrefix("2600:1900::/35"), got[1].Prefix)
}

func TestParseAzure(t *testing.T) {
	data := []byte(`{"values": [
		{"name": "ActionGroup", "properties": {"region": "", "systemService": "ActionGroup",
			"addressPrefixes": ["13.66.60.119/32", "13.67.10.224/27"]}},
		{"name": "Storage.eastus", "properties": {"region": "eastus", "systemService": "AzureStorage",
			"addressPrefixes": ["20.60.0.0/16"]}}
	]}`)

	got, err := ParseFeed(Feed{Format: "azure", HasRegion: true, HasService: true}, data)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "eastus", got[2].Region)
	assert.Equal(t, "AzureStorage", got[2].Service)
}

func TestParseOracle(t *testing.T) {
	data := []byte(`{"regions": [
		{"region": "us-ashburn-1", "cidrs": [
			{"cidr": "129.213.0.0/16", "tags": ["OCI", "OSN"]},
			{"cidr": "130.35.0.0/16", "tags": ["OCI"]}
		]}
	]}`)

	got, err := ParseFeed(Feed{Format: "oracle", HasRegion: true, HasService: true}, data)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "us-ashburn-1", got[0].Region)
	assert.Equal(t, "OCI,OSN", got[0].Service)
}

func TestParseFastly(t *testing.T) {
	data := []byte(`{"addresses": ["23.235.32.0/20", "151.101.0.0/16"], "ipv6_addresses": ["2a04:4e40::/32"]}`)

	got, err := ParseFeed(Feed{Format: "fastly"}, data)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// The feed declares no region or service, so none is kept.
	assert.Empty(t, got[0].Region)
	assert.Empty(t, got[0].Service)
}

func TestParseGitHub(t *testing.T) {
	data := []byte(`{
		"verifiable_password_authentication": false,
		"ssh_key_fingerprints": {"SHA256_RSA": "abc"},
		"hooks": ["192.30.252.0/22"],
		"web": ["140.82.112.0/20", "2a0a:a440::/29"],
		"domains": {"website": ["*.github.com"]}
	}`)

	got, err := ParseFeed(Feed{Format: "github", HasService: true}, data)
	require.NoError(t, err)
	// Only the hooks and web CIDR lists are taken; booleans, fingerprints and
	// the domains map are skipped.
	require.Len(t, got, 3)
	services := map[string]bool{}
	for _, p := range got {
		services[p.Service] = true
	}
	assert.True(t, services["hooks"])
	assert.True(t, services["web"])
}

func TestParseDigitalOceanCSV(t *testing.T) {
	data := []byte("159.65.0.0/16,US,US-NJ,North Bergen,07047\n" +
		"165.227.0.0/16,US,US-CA,Santa Clara,95054\n")

	got, err := ParseFeed(Feed{Format: "digitalocean_csv", HasRegion: true}, data)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "US-NJ", got[0].Region)
	assert.Empty(t, got[0].Service, "the CSV feed carries no service")
}

func TestParseText(t *testing.T) {
	data := []byte("# Cloudflare\n173.245.48.0/20\n\n103.21.244.0/22\n2400:cb00::/32\n")

	got, err := ParseFeed(Feed{Format: "text"}, data)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, netip.MustParsePrefix("173.245.48.0/20"), got[0].Prefix)
}

func TestParseSkipsMalformed(t *testing.T) {
	// A bare address becomes a host route; junk is dropped rather than failing
	// the feed.
	data := []byte("8.8.8.8\nnot-a-cidr\n1.1.1.0/24\n")

	got, err := ParseFeed(Feed{Format: "text"}, data)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, netip.MustParsePrefix("8.8.8.8/32"), got[0].Prefix)
	assert.Equal(t, netip.MustParsePrefix("1.1.1.0/24"), got[1].Prefix)
}

// TestMatcherLongestPrefix checks that the most specific published prefix
// wins, across providers and across IPv4 and IPv6, and that an address in no
// range is unattributed.
func TestMatcherLongestPrefix(t *testing.T) {
	aws := Provider{Key: "aws", Organization: "Amazon Web Services"}
	gcp := Provider{Key: "gcp", Organization: "Google Cloud"}

	m := NewMatcher()
	m.Add(aws, []Prefix{
		{Prefix: netip.MustParsePrefix("52.0.0.0/8"), Region: "us-east-1", Service: "EC2"},
		{Prefix: netip.MustParsePrefix("52.95.0.0/16"), Region: "us-east-1", Service: "S3"},
		{Prefix: netip.MustParsePrefix("2600:9000::/28"), Region: "GLOBAL", Service: "CLOUDFRONT"},
	})
	m.Add(gcp, []Prefix{{Prefix: netip.MustParsePrefix("34.64.0.0/10"), Region: "asia", Service: "GCP"}})

	// The /16 is more specific than the /8, so the service is S3, not EC2.
	got, ok := m.Match(netip.MustParseAddr("52.95.1.1"))
	require.True(t, ok)
	assert.Equal(t, "aws", got.ProviderKey)
	assert.Equal(t, "S3", got.Service)
	assert.Equal(t, netip.MustParsePrefix("52.95.0.0/16"), got.Prefix)

	// An address covered only by the /8 falls back to it.
	got, ok = m.Match(netip.MustParseAddr("52.1.2.3"))
	require.True(t, ok)
	assert.Equal(t, "EC2", got.Service)

	// A different provider.
	got, ok = m.Match(netip.MustParseAddr("34.64.1.1"))
	require.True(t, ok)
	assert.Equal(t, "Google Cloud", got.Organization)

	// IPv6 match.
	got, ok = m.Match(netip.MustParseAddr("2600:9000:1::5"))
	require.True(t, ok)
	assert.Equal(t, "CLOUDFRONT", got.Service)

	// An address in no published range is unattributed.
	_, ok = m.Match(netip.MustParseAddr("8.8.8.8"))
	assert.False(t, ok)
}

// TestMatcherIPv4MappedV6 checks an IPv4-mapped IPv6 address matches the IPv4
// ranges.
func TestMatcherIPv4MappedV6(t *testing.T) {
	m := NewMatcher()
	m.Add(Provider{Key: "aws", Organization: "Amazon Web Services"},
		[]Prefix{{Prefix: netip.MustParsePrefix("52.95.0.0/16")}})

	got, ok := m.Match(netip.MustParseAddr("::ffff:52.95.1.1"))
	require.True(t, ok)
	assert.Equal(t, "aws", got.ProviderKey)
}
