// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package reputation

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func listings(t *testing.T, sess *plugintest.Session, ent *dbt.Entity) []string {
	t.Helper()

	tags, err := sess.DB().FindEntityTags(context.Background(), ent, time.Time{}, PropListing)
	if err != nil {
		return nil
	}
	var out []string
	for _, tag := range tags {
		out = append(out, tag.Property.Value())
	}
	slices.Sort(out)
	return out
}

// Each feed format is read, comments and private space are skipped, and
// addresses and netblocks are matched against the ranges.
func TestFeedsMatchAddressesAndNetblocks(t *testing.T) {
	sess := plugintest.NewSession(t)
	web := sess.Web()
	web.Reply("GET www.spamhaus.org/drop/drop_v4.json", http.StatusOK,
		`{"cidr":"198.51.100.0/24","sblid":"SBL1","rir":"arin"}`+"\n"+`{"type":"metadata","records":1}`)
	web.Reply("GET www.spamhaus.org/drop/drop_v6.json", http.StatusOK, `{"type":"metadata","records":0}`)
	web.Reply("GET check.torproject.org/torbulkexitlist", http.StatusOK, "203.0.113.7\n")
	web.Reply("GET raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", http.StatusOK,
		"# FireHOL level 1\n10.0.0.0/8\n192.0.2.0/24\n198.51.100.128/25\n")

	r := NewReputation().(*reputation)
	r.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	r.dir = t.TempDir()
	r.feeds = newFeeds(semantics.ReputationFeedCatalog(), r.dir)

	check := func(ent *dbt.Entity, fn func(*et.Event) error) []string {
		if err := fn(&et.Event{Entity: ent, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
			t.Fatal(err)
		}
		return listings(t, sess, ent)
	}
	ip := func(s string) *dbt.Entity {
		return sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr(s), Type: "IPv4"})
	}
	nb := func(s string) *dbt.Entity {
		return sess.Asset(t, &oamnet.Netblock{CIDR: netip.MustParsePrefix(s), Type: "IPv4"})
	}

	if got := check(ip("198.51.100.200"), r.checkAddress); !slices.Equal(got, []string{"firehol-level1",
		"spamhaus-drop"}) {
		t.Errorf("an address on two feeds: %v", got)
	}
	if got := check(ip("203.0.113.7"), r.checkAddress); !slices.Equal(got, []string{"tor-exit"}) {
		t.Errorf("a Tor exit: %v", got)
	}
	if got := check(ip("10.1.2.3"), r.checkAddress); len(got) != 0 {
		t.Errorf("private space was flagged: %v", got)
	}
	if got := check(nb("198.51.100.0/23"), r.checkNetblock); !slices.Equal(got, []string{"firehol-level1",
		"spamhaus-drop"}) {
		t.Errorf("a netblock holding listed ranges: %v", got)
	}
	if got := check(nb("198.51.100.0/26"), r.checkNetblock); !slices.Equal(got, []string{"spamhaus-drop"}) {
		t.Errorf("a netblock inside a listed range: %v", got)
	}
	if got := check(nb("203.0.113.0/25"), r.checkNetblock); !slices.Equal(got, []string{"tor-exit"}) {
		t.Errorf("a netblock holding a Tor exit: %v", got)
	}

	// within the refresh period the feeds are not downloaded again
	before := len(web.Requests())
	_ = check(ip("198.51.100.1"), r.checkAddress)
	if len(web.Requests()) != before {
		t.Errorf("downloaded again: %v", web.Requests()[before:])
	}
}

func TestListedRange(t *testing.T) {
	for in, want := range map[string]string{"198.51.100.7": "198.51.100.7/32", "2001:db8::/32": "2001:db8::/32",
		"192.168.0.0/16": "", "203.0.113.0/24": "203.0.113.0/24", "bogus": ""} {
		got := ""
		if n := listedRange(in); n != nil {
			got = n.String()
		}
		if got != want {
			t.Errorf("listedRange(%q) = %q, want %q", in, got, want)
		}
	}
	if !covers(mustNet("198.51.100.0/24"), mustNet("198.51.100.0/26")) ||
		covers(mustNet("198.51.100.0/26"), mustNet("198.51.100.0/24")) {
		t.Error("covers")
	}
}

func mustNet(s string) *net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return n
}
