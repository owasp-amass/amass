// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func simpleProperty(name, value string) graph.Evidence {
	return graph.Evidence{Kind: "SimpleProperty", Property: map[string]any{"property_name": name, "property_value": value}}
}

// webSignalsFixture adds web fingerprints to moreSignalsFixture: www.colgate.edu's
// service carries an analytics ID, a favicon hash, a distinctive title and a
// generic one, and other names, a URL and many services share some of them.
func webSignalsFixture() valueGraph {
	g := moreSignalsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	hosted := func(name, svc string, ev ...graph.Evidence) {
		add(name, "FQDN", name, map[string]any{"name": name})
		add(svc, "Service", svc, map[string]any{"unique_id": svc})
		link(name, "port", svc, "PortRelation")
		g.EvidenceByID[svc] = ev
	}

	g.EvidenceByID["svc-www"] = append(g.EvidenceByID["svc-www"],
		simpleProperty(fingerprint.AnalyticsID, "GTM-K9X2ZQ"),
		simpleProperty(fingerprint.FaviconMMH3, "-1234567890"),
		simpleProperty(fingerprint.Title, "Colgate University Alumni Portal"),
		simpleProperty(fingerprint.Title, "403 Forbidden"))

	hosted("analytics-twin.example", "svc-at", simpleProperty(fingerprint.AnalyticsID, "GTM-K9X2ZQ"))
	hosted("title-twin.example", "svc-tt", simpleProperty(fingerprint.Title, "Colgate University Alumni Portal"))
	hosted("forbidden.example", "svc-fb", simpleProperty(fingerprint.Title, "403 Forbidden"))
	add("url-promo", "URL", "https://promo.example/landing", map[string]any{"url": "https://promo.example/landing"})
	g.EvidenceByID["url-promo"] = []graph.Evidence{simpleProperty(fingerprint.AnalyticsID, "GTM-K9X2ZQ")}
	for i := 0; i <= lens.GapMaxShared; i++ {
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
		t.Errorf("a favicon on more than %d services counted: %+v", lens.GapMaxShared, c)
	}

	// Supporting fingerprints alone never propose, however many there are.
	if c := candidateByID(r, "analytics-twin.example"); c != nil && c.Decision == lens.GapPropose {
		t.Errorf("an analytics ID alone was proposed: %+v", c)
	}
}

func TestSSHHostKeyReuse(t *testing.T) {
	g := webSignalsFixture()
	key := simpleProperty(fingerprint.SSHHostKey, "ssh-ed25519 SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	service := func(host, svc string) {
		g.Assets[svc] = graph.Asset{ID: svc, Type: "Service", Key: svc, Content: map[string]any{"unique_id": svc,
			"service_type": "ssh"}}
		g.Links = append(g.Links, graph.Relation{ID: host + "-port-" + svc, FromID: host, ToID: svc, Label: "port",
			Type: "PortRelation"})
		g.EvidenceByID[svc] = []graph.Evidence{key}
	}

	// The same key on an address in Colgate's netblock and on another.
	service("ip-own", "svc-ssh-own")
	g.Assets["ip-twin"] = graph.Asset{ID: "ip-twin", Type: "IPAddress", Key: "198.51.100.7",
		Content: map[string]any{"address": "198.51.100.7"}}
	service("ip-twin", "svc-ssh-twin")

	c := candidateByID(signalsReport(t, g), "ip-twin")
	if c == nil || !slices.Equal(signalIDs(c), []string{"ssh_host_key_reuse"}) {
		t.Fatalf("ip-twin = %+v", c)
	}

	def, _ := lens.LookupOwnershipSignal("ssh_host_key_reuse")
	if def.Strength != lens.StrengthStrong {
		t.Errorf("ssh_host_key_reuse is %s, want strong", def.Strength)
	}
}
