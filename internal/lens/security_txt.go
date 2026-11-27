// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// A stored security.txt (engine plugin security_txt) is its URL, joined to
// its domain, with the file's ContactRecord (URL --contact--> ContactRecord):
// Contact entries as the record's email Identifiers, phones and URLs, the
// URL-valued fields as URLs whose url relation carries the field name, and
// Expires as a record property.
const (
	secTxtPropField   = "security_txt_field"
	secTxtPropExpires = "security_txt_expires"
)

// securityTxtPaths are where a security.txt is served.
var securityTxtPaths = []string{"/.well-known/security.txt", "/security.txt"}

// isSecurityTxtURL reports whether a URL is a security.txt location.
func isSecurityTxtURL(u graph.Asset) bool {
	return u.Type == "URL" && slices.Contains(securityTxtPaths, graph.ContentString(u, "path"))
}

// hostFiles returns the stored URLs of the files at paths on a host: found by
// URL when the graph resolves assets, otherwise among the URLs whose domain
// is the host.
func hostFiles(ctx context.Context, g graph.Graph, host graph.Asset, paths []string) []graph.Asset {
	name := graph.FQDNName(host)
	if name == "" {
		return nil
	}

	var out []graph.Asset
	if resolver, ok := g.(graph.AssetResolver); ok {
		for _, p := range paths {
			res, err := resolver.ResolveAsset(ctx, graph.AssetSelector{Type: "URL", Field: "url",
				Value: "https://" + name + p}, 2)
			if err == nil && len(res.Candidates) > 0 {
				out = append(out, res.Candidates[0].Asset)
			}
		}
		return out
	}

	edges, err := g.Edges(ctx, host.ID, "in", "domain", time.Time{})
	if err != nil {
		return nil
	}
	for _, e := range edges {
		if u, err := g.GetAsset(ctx, e.FromID); err == nil && u.Type == "URL" &&
			slices.Contains(paths, graph.ContentString(u, "path")) {
			out = append(out, u)
		}
	}
	return out
}

// securityTxt is what one stored security.txt says.
type securityTxt struct {
	file     graph.Asset
	record   graph.Asset
	contacts []string // email addresses, phones and contact URLs
	links    []string // "<field>: <url>"
	urls     []securityTxtURL
	expires  string
}

// securityTxtURL is a URL a security.txt names, and the field it came from
// ("" for a Contact entry).
type securityTxtURL struct {
	url   graph.Asset
	field string
}

// readSecurityTxt reads the security.txt files stored for a host.
func readSecurityTxt(ctx context.Context, g graph.Graph, host graph.Asset) []securityTxt {
	er, _ := g.(graph.EdgeEvidenceReader)
	var out []securityTxt
	for _, file := range hostFiles(ctx, g, host, securityTxtPaths) {
		crs, err := g.Edges(ctx, file.ID, "out", "contact", time.Time{})
		if err != nil {
			continue
		}
		for _, ce := range crs {
			cr, err := g.GetAsset(ctx, ce.ToID)
			if err != nil {
				continue
			}
			out = append(out, readSecurityTxtRecord(ctx, g, er, file, cr))
		}
	}
	return out
}

// readSecurityTxtRecord reads one file's ContactRecord.
func readSecurityTxtRecord(ctx context.Context, g graph.Graph, er graph.EdgeEvidenceReader, file,
	cr graph.Asset) securityTxt {
	st := securityTxt{file: file, record: cr}
	edges, err := g.Edges(ctx, cr.ID, "out", "", time.Time{})
	if err != nil {
		return st
	}
	for _, e := range edges {
		other, err := g.GetAsset(ctx, e.ToID)
		if err != nil {
			continue
		}
		switch e.Label {
		case "id":
			if strings.EqualFold(graph.ContentString(other, "id_type"), "email") {
				graph.AddUnique(&st.contacts, graph.ContentString(other, "id"))
			}
		case "phone":
			graph.AddUnique(&st.contacts, graph.AssetLabel(other))
		case "url":
			field := ""
			if er != nil {
				if ev, err := er.EdgeEvidence(ctx, e.ID, 20); err == nil {
					if v := propertyValues(ev, secTxtPropField); len(v) > 0 {
						field = v[0]
					}
				}
			}
			st.urls = append(st.urls, securityTxtURL{url: other, field: field})
			if field == "" {
				graph.AddUnique(&st.contacts, graph.AssetLabel(other))
			} else {
				graph.AddUnique(&st.links, field+": "+graph.AssetLabel(other))
			}
		}
	}
	if ev, err := g.Evidence(ctx, cr.ID, 50); err == nil {
		if v := propertyValues(ev, secTxtPropExpires); len(v) > 0 {
			st.expires = v[0]
		}
	}
	sort.Strings(st.contacts)
	sort.Strings(st.links)
	return st
}

// securityTxtFilesOf returns the security.txt files whose ContactRecord is cr.
func securityTxtFilesOf(ctx context.Context, g graph.Graph, cr graph.Asset) []graph.Asset {
	edges, err := g.Edges(ctx, cr.ID, "in", "contact", time.Time{})
	if err != nil {
		return nil
	}
	var out []graph.Asset
	for _, e := range edges {
		if u, err := g.GetAsset(ctx, e.FromID); err == nil && isSecurityTxtURL(u) {
			out = append(out, u)
		}
	}
	return out
}

// fileHost returns the FQDN a file's URL is on.
func fileHost(ctx context.Context, g graph.Graph, file graph.Asset) (graph.Asset, bool) {
	edges, err := g.Edges(ctx, file.ID, "out", "domain", time.Time{})
	if err != nil {
		return graph.Asset{}, false
	}
	for _, e := range edges {
		if fq, err := g.GetAsset(ctx, e.ToID); err == nil && fq.Type == "FQDN" {
			return fq, true
		}
	}
	return graph.Asset{}, false
}
