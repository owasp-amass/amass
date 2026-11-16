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

// securityTxtRelations are the Service relations a security.txt populates.
var securityTxtLinkRelations = map[string]string{
	"security_policy":          "policy",
	"security_canonical":       "canonical",
	"security_encryption":      "encryption",
	"security_acknowledgments": "acknowledgments",
	"security_hiring":          "hiring",
}

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

// FindDisclosure reports the security.txt published for the services a domain
// or organization controls: their security contacts and policy links, and
// which files have expired. It walks the controlled footprint and reads only.
func FindDisclosure(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (DisclosureReport, error) {
	out := DisclosureReport{}
	s, err := newScope(ctx, g, schema, root, limits, "disclosure")
	if err != nil {
		return out, err
	}

	seen := map[string]bool{}
	for _, id := range s.order {
		if s.spent() {
			break
		}

		host := s.owned[id]
		if host.Type != "FQDN" {
			continue
		}
		steps, err := s.w.steps(host)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "Service" || seen[st.other.ID] {
				continue
			}

			file, ok, err := s.w.securityTxtOf(st.other, graph.FQDNName(host))
			if err != nil {
				return out, err
			}
			if !ok {
				continue
			}
			seen[st.other.ID] = true
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

// securityTxtOf reads the security.txt a service published: its contacts, its
// policy links and its expiry. It returns ok=false when the service has no
// security_contact relation, which marks a service that published no file.
func (w *lensWalker) securityTxtOf(service graph.Asset, host string) (DisclosureFile, bool, error) {
	file := DisclosureFile{Host: host}
	steps, err := w.steps(service)
	if err != nil {
		return file, false, err
	}

	var found bool
	for _, s := range steps {
		if !s.forward {
			continue
		}
		switch {
		case s.edge.Label == "security_contact" && s.other.Type == "ContactRecord":
			found = true
			file.Contacts = append(file.Contacts, w.contactValues(s.other)...)
		default:
			if kind, ok := securityTxtLinkRelations[s.edge.Label]; ok {
				found = true
				graph.AddUnique(&file.Links, kind+": "+graph.AssetLabel(s.other))
			}
		}
	}
	if !found {
		return file, false, nil
	}

	if ev, err := w.graph.Evidence(w.ctx, service.ID, 100); err == nil {
		if vals := propertyValues(ev, "security_txt_expires"); len(vals) > 0 {
			file.Expires = vals[0]
			if t, ok := parseExpires(file.Expires); ok && t.Before(disclosureNow()) {
				file.Expired = true
			}
		}
	}

	sort.Strings(file.Contacts)
	sort.Strings(file.Links)
	return file, true, nil
}

// contactValues returns the email, URL and phone values of a contact record.
func (w *lensWalker) contactValues(cr graph.Asset) []string {
	steps, err := w.steps(cr)
	if err != nil {
		return nil
	}

	var out []string
	for _, s := range steps {
		if !s.forward {
			continue
		}
		switch s.edge.Label {
		case "id":
			if strings.EqualFold(graph.ContentString(s.other, "id_type"), "email") {
				graph.AddUnique(&out, graph.ContentString(s.other, "id"))
			}
		case "url":
			graph.AddUnique(&out, graph.AssetLabel(s.other))
		case "phone":
			graph.AddUnique(&out, graph.AssetLabel(s.other))
		}
	}
	return out
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
	if len(r.Files) == 0 {
		b.WriteString("\nNo security.txt is stored for its services.\n")
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
