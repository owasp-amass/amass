// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensDisclosure asks how a domain or organization publishes its security
// contact and vulnerability-disclosure policy, through security.txt.
const LensDisclosure = "disclosure"

var disclosureLens = SubjectLens{
	Name:    LensDisclosure,
	Command: "disclosure",
	Description: "Show how a domain or organization invites vulnerability reports: the security.txt security " +
		"contacts, policy and encryption links, and which files are expired. Read-only",
	Examples: []string{"Who do I contact about security at <organization>?",
		"Which of <domain>'s security.txt files have expired?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindDisclosure(ctx, g, schema, root, opts.Limits)
	},
}

// Disclosure finding kinds.
const DisclosureExpired = "expired"

// DisclosureReport is the result of the disclosure lens.
type DisclosureReport struct {
	lensBase
	Files    []DisclosureFile    `json:"files"`
	Findings []DisclosureFinding `json:"findings,omitempty"`
}

// DisclosureFile is a domain's published security.txt posture.
type DisclosureFile struct {
	Host     string   `json:"host"`
	Contacts []string `json:"contacts,omitempty"`
	Links    []string `json:"links,omitempty"`
	Expires  string   `json:"expires,omitempty"`
	Expired  bool     `json:"expired,omitempty"`
}

// DisclosureFinding is a security.txt problem worth attention.
type DisclosureFinding struct {
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Detail string `json:"detail"`
}

// disclosureNow is the clock the expiry is measured against; tests replace it.
var disclosureNow = time.Now

// FindDisclosure reports the security.txt files published on the names a
// domain or organization controls: their security contacts and policy links,
// and which files have expired. It walks the controlled footprint and reads
// only.
func FindDisclosure(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (DisclosureReport, error) {
	out := DisclosureReport{}
	s, err := newScope(ctx, g, schema, root, limits, "disclosure")
	if err != nil {
		return out, err
	}

	for _, id := range s.order {
		if s.spent() {
			break
		}

		host := s.owned[id]
		if host.Type != "FQDN" {
			continue
		}
		for _, st := range readSecurityTxt(ctx, s.w.graph, host) {
			file := DisclosureFile{Host: graph.FQDNName(host), Contacts: st.contacts, Links: st.links,
				Expires: st.expires}
			if t, ok := parseExpires(st.expires); ok && t.Before(disclosureNow()) {
				file.Expired = true
			}
			out.Files = append(out.Files, file)
			if file.Expired {
				out.Findings = append(out.Findings, DisclosureFinding{Kind: DisclosureExpired, Host: file.Host,
					Detail: "its security.txt expired " + file.Expires + ", so the reporting details may be stale"})
			}
		}
	}

	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Host < out.Files[j].Host })
	out.lensBase = s.base()
	return out, nil
}

// parseExpires reads the RFC 9116 Expires field (an RFC 3339 timestamp).
func parseExpires(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (r DisclosureReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Vulnerability-disclosure posture of %s, from %d controlled asset(s) (%d reads).\n",
		subject, r.Footprint, r.Reads)
	b.WriteString(r.summarizedNote())
	if len(r.Files) == 0 {
		b.WriteString("\nNo security.txt is stored for its domains.\n")
		return b.String()
	}

	for _, f := range r.Files {
		status := ""
		if f.Expired {
			status = " (EXPIRED " + f.Expires + ")"
		} else if f.Expires != "" {
			status = " (expires " + f.Expires + ")"
		}
		fmt.Fprintf(&b, "\n%s%s\n", f.Host, status)
		if len(f.Contacts) > 0 {
			fmt.Fprintf(&b, "  contacts: %s\n", strings.Join(f.Contacts, ", "))
		}
		for _, l := range f.Links {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}

	b.WriteString(r.partialNote() + "\n")
	return b.String()
}

func (r DisclosureReport) Facts() []string {
	var out []string
	for _, f := range r.Files {
		out = append(out, "security.txt for "+f.Host)
	}
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Host)
	}
	return out
}
