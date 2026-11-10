// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
)

// TestWebSignalsUseTheFingerprintContract keeps the catalog's property
// names equal to the names every collector stores.
func TestWebSignalsUseTheFingerprintContract(t *testing.T) {
	want := map[string]string{
		"shared_analytics_id": fingerprint.AnalyticsID,
		"same_favicon":        fingerprint.FaviconMMH3,
		"same_page_content":   fingerprint.BodySHA256,
		"same_page_title":     fingerprint.Title,
		"ssh_host_key_reuse":  fingerprint.SSHHostKey,
	}
	for id, prop := range want {
		def, ok := ownershipSignal(id)
		if !ok || def.Params.Property != prop {
			t.Errorf("signal %s reads %q, collectors store %q", id, def.Params.Property, prop)
		}
	}
}

func simpleProperty(name, value string) Evidence {
	return Evidence{Kind: "SimpleProperty", Property: map[string]any{"property_name": name, "property_value": value}}
}

// webSignalsFixture adds web fingerprints to moreSignalsFixture: www.colgate.edu's
// service carries an analytics ID, a favicon hash, a distinctive title and a
// generic one, and other names, a URL and many services share some of them.
func webSignalsFixture() valueGraph {
	g := moreSignalsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	hosted := func(name, svc string, ev ...Evidence) {
		add(name, "FQDN", name, map[string]any{"name": name})
		add(svc, "Service", svc, map[string]any{"unique_id": svc})
		link(name, "port", svc, "PortRelation")
		g.evidence[svc] = ev
	}

	g.evidence["svc-www"] = append(g.evidence["svc-www"],
		simpleProperty(fingerprint.AnalyticsID, "GTM-K9X2ZQ"),
		simpleProperty(fingerprint.FaviconMMH3, "-1234567890"),
		simpleProperty(fingerprint.Title, "Colgate University Alumni Portal"),
		simpleProperty(fingerprint.Title, "403 Forbidden"))

	hosted("analytics-twin.example", "svc-at", simpleProperty(fingerprint.AnalyticsID, "GTM-K9X2ZQ"))
	hosted("title-twin.example", "svc-tt", simpleProperty(fingerprint.Title, "Colgate University Alumni Portal"))
	hosted("forbidden.example", "svc-fb", simpleProperty(fingerprint.Title, "403 Forbidden"))
	add("url-promo", "URL", "https://promo.example/landing", map[string]any{"url": "https://promo.example/landing"})
	g.evidence["url-promo"] = []Evidence{simpleProperty(fingerprint.AnalyticsID, "GTM-K9X2ZQ")}
	for i := 0; i <= gapMaxShared; i++ {
		hosted(fmt.Sprintf("default-icon-%d.example", i), fmt.Sprintf("svc-icon-%d", i),
			simpleProperty(fingerprint.FaviconMMH3, "-1234567890"))
	}

	return g
}

func TestWebFingerprintSignals(t *testing.T) {
	r := signalsReport(t, webSignalsFixture())
	for id, want := range map[string]string{
		"analytics-twin.example": "shared_analytics_id",
		"url-promo":              "shared_analytics_id",
		"title-twin.example":     "same_page_title",
	} {
		c := candidateByID(r, id)
		if c == nil || !slices.Contains(signalIDs(c), want) {
			t.Errorf("%s = %+v, want %s", id, c, want)
		}
	}
	if c := candidateByID(r, "forbidden.example"); c != nil {
		t.Errorf("a generic page title counted: %+v", c)
	}
	if c := candidateByID(r, "default-icon-0.example"); c != nil {
		t.Errorf("a favicon on more than %d services counted: %+v", gapMaxShared, c)
	}

	// Supporting fingerprints alone never propose, however many there are.
	if c := candidateByID(r, "analytics-twin.example"); c != nil && c.Decision == GapPropose {
		t.Errorf("an analytics ID alone was proposed: %+v", c)
	}
}

func TestClonedSitesAreNeverProposed(t *testing.T) {
	// A copy of a page carries its analytics IDs, favicon, content and title.
	clone := []GapSignal{{Signal: "shared_analytics_id"}, {Signal: "same_favicon"}, {Signal: "same_page_content"},
		{Signal: "same_page_title"}}
	if _, d := scoreGap(clone, true); d != GapReview {
		t.Errorf("a cloned site = %s, want review", d)
	}
}

func TestSSHHostKeyReuse(t *testing.T) {
	g := webSignalsFixture()
	key := simpleProperty(fingerprint.SSHHostKey, "ssh-ed25519 SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	service := func(host, svc string) {
		g.assets[svc] = Asset{ID: svc, Type: "Service", Key: svc, Content: map[string]any{"unique_id": svc,
			"service_type": "ssh"}}
		g.links = append(g.links, Relation{ID: host + "-port-" + svc, FromID: host, ToID: svc, Label: "port",
			Type: "PortRelation"})
		g.evidence[svc] = []Evidence{key}
	}

	// The same key on an address in Colgate's netblock and on another.
	service("ip-own", "svc-ssh-own")
	g.assets["ip-twin"] = Asset{ID: "ip-twin", Type: "IPAddress", Key: "198.51.100.7",
		Content: map[string]any{"address": "198.51.100.7"}}
	service("ip-twin", "svc-ssh-twin")

	c := candidateByID(signalsReport(t, g), "ip-twin")
	if c == nil || !slices.Equal(signalIDs(c), []string{"ssh_host_key_reuse"}) {
		t.Fatalf("ip-twin = %+v", c)
	}

	def, _ := ownershipSignal("ssh_host_key_reuse")
	if def.Strength != StrengthStrong {
		t.Errorf("ssh_host_key_reuse is %s, want strong", def.Strength)
	}
}
