// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/semantics"
)

var servicesJSON = semantics.File("services.json")

type serviceRules struct {
	License              string           `json:"_license"`
	About                string           `json:"_about"`
	ServiceRelationTypes []string         `json:"service_relation_types"`
	CertificatePurpose   string           `json:"certificate_purpose"`
	ProductPurpose       string           `json:"product_purpose"`
	SoftwareHeaders      []string         `json:"software_headers"`
	ExpectedPorts        map[string][]int `json:"expected_ports"`
	CertWarningDays      int              `json:"certificate_warning_days"`
}

var loadServiceRules = sync.OnceValue(func() serviceRules {
	var r serviceRules
	if err := graph.DecodeStrict(servicesJSON, &r); err != nil {
		panic("services.json: " + err.Error())
	}
	if len(r.ServiceRelationTypes) == 0 || r.CertificatePurpose == "" || r.CertWarningDays < 1 {
		panic("services.json: service_relation_types, certificate_purpose and certificate_warning_days are required")
	}

	return r
})

// serviceNow is the clock certificate expiry is measured against; tests
// replace it.
var serviceNow = time.Now

// ServiceCertificate is a certificate a service presented.
type ServiceCertificate struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer,omitempty"`
	NotAfter string `json:"not_after,omitempty"`
	// Expired and ExpiresSoon compare NotAfter with the time of the run;
	// SelfIssued reports a certificate whose issuer is its subject.
	Expired     bool `json:"expired,omitempty"`
	ExpiresSoon bool `json:"expires_soon,omitempty"`
	SelfIssued  bool `json:"self_issued,omitempty"`
}

// ExposedService is one stored service and where it listens.
type ExposedService struct {
	Service     graph.Asset `json:"service"`
	ServiceType string      `json:"service_type,omitempty"`
	Endpoints   []string    `json:"endpoints"`
	Ports       []string    `json:"ports"`
	Software    []string    `json:"software,omitempty"`
	Products    []string    `json:"products,omitempty"`
	// Identified is software the stored headers or banner name, matched by
	// the fingerprint catalog; Products are the products stored for it.
	Identified   []IdentifiedProduct  `json:"identified,omitempty"`
	Certificates []ServiceCertificate `json:"certificates,omitempty"`
	// UnusualPorts are ports outside expected_ports for the service type.
	UnusualPorts []string `json:"unusual_ports,omitempty"`
}

// ServicesReport is the result of the services lens.
type ServicesReport struct {
	Root      graph.Asset      `json:"root"`
	Owners    []string         `json:"owners,omitempty"`
	Footprint int              `json:"footprint"`
	Hosts     int              `json:"hosts"`
	Services  []ExposedService `json:"services"`
	ByType    map[string]int   `json:"by_type"`
	// ByProduct counts the services each identified product and version
	// runs on ("nginx 1.18.0").
	ByProduct map[string]int `json:"by_product"`
	ByPort    map[string]int `json:"by_port"`
	Reads     int            `json:"reads"`
	Truncated bool           `json:"truncated"`
	Reason    string         `json:"reason,omitempty"`
}

// LensServices asks for the services stored for what a domain or
// organization controls, with the software they run and their
// certificates. The answer is built in Go; nothing is written.
const LensServices = "services"

// FindServices lists the services stored for the names, addresses and URLs
// a domain or organization controls, with their ports, the software their
// responses name, their certificates and products, and what stands out:
// unusual ports and expired, expiring or self-issued certificates. It walks
// the controlled footprint as the vendors lens does and reads only.
func FindServices(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (ServicesReport, error) {
	out := ServicesReport{Root: root, ByType: map[string]int{}, ByPort: map[string]int{}, ByProduct: map[string]int{}}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return out, errors.New("the services lens requires relationship semantics")
	}
	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}
	if err := limits.Validate(); err != nil {
		return out, err
	}

	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}}
	w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, &report)
	w.maxAssets, w.maxReads = limits.assets(), limits.reads()
	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return out, err
	}
	for _, o := range owners {
		out.Owners = append(out.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return out, err
	}
	out.Footprint = len(owned)

	rules := loadServiceRules()
	services := map[string]*ExposedService{}
	var ids []string
	hosts := map[string]bool{}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if report.Reads >= w.maxReads {
			w.truncate("database read limit")
			break
		}

		host := owned[id]
		steps, err := w.steps(host)
		if err != nil {
			return out, err
		}
		for _, s := range steps {
			if !s.forward || !slices.Contains(rules.ServiceRelationTypes, s.edge.Type) {
				continue
			}

			svc, ok := services[s.other.ID]
			if !ok {
				svc, err = describeService(w, s.other, rules)
				if err != nil {
					return out, err
				}
				services[s.other.ID] = svc
				ids = append(ids, s.other.ID)
			}

			hosts[host.ID] = true
			port := RelationDetail(s.edge)
			endpoint := graph.AssetLabel(host)
			if port != "" {
				endpoint += ":" + strings.Split(port, "/")[0]
			}
			graph.AddUnique(&svc.Endpoints, endpoint)
			if port != "" {
				graph.AddUnique(&svc.Ports, port)
				if !portExpected(rules, svc.ServiceType, port) {
					graph.AddUnique(&svc.UnusualPorts, port)
				}
			}
		}
	}

	for _, id := range ids {
		svc := services[id]
		sort.Strings(svc.Endpoints)
		sort.Strings(svc.Ports)
		out.Services = append(out.Services, *svc)
		kind := svc.ServiceType
		if kind == "" {
			kind = "unknown"
		}
		out.ByType[kind]++
		for _, p := range svc.Ports {
			out.ByPort[p]++
		}
		for _, p := range svc.Identified {
			out.ByProduct[strings.TrimSpace(p.Product+" "+p.Version)]++
		}
	}
	sort.SliceStable(out.Services, func(i, j int) bool {
		a, b := out.Services[i], out.Services[j]
		if serviceNotable(a) != serviceNotable(b) {
			return serviceNotable(a)
		}
		if len(a.Endpoints) != len(b.Endpoints) {
			return len(a.Endpoints) > len(b.Endpoints)
		}
		return a.Service.ID < b.Service.ID
	})

	out.Hosts = len(hosts)
	out.Reads = report.Reads
	out.Truncated, out.Reason = report.Truncated, report.Reason
	return out, nil
}

// describeService reads a service's type, the software its response
// headers name, and the certificates and products stored for it.
func describeService(w *lensWalker, svc graph.Asset, rules serviceRules) (*ExposedService, error) {
	out := &ExposedService{Service: svc, ServiceType: graph.ContentString(svc, "service_type")}
	out.Software = softwareHeaders(svc, rules.SoftwareHeaders)
	out.Identified = identifyProducts(svc)

	steps, err := w.steps(svc)
	if err != nil {
		return nil, err
	}
	for _, s := range steps {
		if !s.forward {
			continue
		}
		switch s.purpose {
		case rules.CertificatePurpose:
			out.Certificates = append(out.Certificates, certificateOf(s.other, rules.CertWarningDays))
		case rules.ProductPurpose:
			graph.AddUnique(&out.Products, graph.AssetLabel(s.other))
		}
	}

	return out, nil
}

// softwareHeaders returns "header: value" for the stored response headers
// whose names are in names.
func softwareHeaders(svc graph.Asset, names []string) []string {
	data, err := json.Marshal(svc.Content)
	if err != nil {
		return nil
	}
	var f struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil
	}

	var out []string
	for key, values := range f.Attributes {
		if !slices.Contains(names, strings.ToLower(key)) {
			continue
		}
		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" {
				graph.AddUnique(&out, strings.ToLower(key)+": "+v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// certificateOf summarizes a certificate and how it compares with the time
// of the run.
func certificateOf(cert graph.Asset, warningDays int) ServiceCertificate {
	c := ServiceCertificate{Subject: graph.ContentString(cert, "subject_common_name"),
		Issuer: graph.ContentString(cert, "issuer_common_name"), NotAfter: graph.ContentString(cert, "not_after")}
	if c.Subject == "" {
		c.Subject = graph.AssetLabel(cert)
	}
	c.SelfIssued = c.Issuer != "" && strings.EqualFold(c.Issuer, c.Subject)

	if t, err := time.Parse(time.RFC3339, c.NotAfter); err == nil {
		now := serviceNow()
		c.Expired = t.Before(now)
		c.ExpiresSoon = !c.Expired && t.Before(now.AddDate(0, 0, warningDays))
	}

	return c
}

// portExpected reports whether a port ("443/TCP") is one expected_ports lists
// for the service type; a type without a list expects any port.
func portExpected(rules serviceRules, kind, port string) bool {
	ports, ok := rules.ExpectedPorts[kind]
	if !ok {
		return true
	}

	var n int
	if _, err := fmt.Sscanf(port, "%d", &n); err != nil {
		return true
	}
	return slices.Contains(ports, n)
}

func serviceNotable(s ExposedService) bool {
	if len(s.UnusualPorts) > 0 {
		return true
	}
	for _, c := range s.Certificates {
		if c.Expired || c.ExpiresSoon || c.SelfIssued {
			return true
		}
	}

	return false
}

// FormatServicesReport renders the services lens for a terminal.
func FormatServicesReport(r ServicesReport) string {
	var b strings.Builder
	scope := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		scope += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Services exposed by %s: %d service(s) on %d host(s), from %d controlled asset(s) (%d reads).\n",
		scope, len(r.Services), r.Hosts, r.Footprint, r.Reads)
	if len(r.Services) == 0 {
		b.WriteString("No service is stored for its names, addresses or URLs. Services are stored by the HTTP and " +
			"SSH probes during an active enumeration.\n")
		return b.String()
	}

	counts := func(title string, m map[string]int) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if m[keys[i]] != m[keys[j]] {
				return m[keys[i]] > m[keys[j]]
			}
			return keys[i] < keys[j]
		})
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
		}
		fmt.Fprintf(&b, "%s: %s\n", title, strings.Join(parts, ", "))
	}
	counts("By type", r.ByType)
	counts("By port", r.ByPort)
	if len(r.ByProduct) > 0 {
		counts("Identified software", r.ByProduct)
	}

	var notes []string
	for _, s := range r.Services {
		where := s.Endpoints[0]
		if len(s.Endpoints) > 1 {
			where += fmt.Sprintf(" and %d more", len(s.Endpoints)-1)
		}
		for _, p := range s.UnusualPorts {
			notes = append(notes, fmt.Sprintf("%s service on unusual port %s (%s)", s.ServiceType, p, where))
		}
		for _, c := range s.Certificates {
			switch {
			case c.Expired:
				notes = append(notes, fmt.Sprintf("expired certificate for %s since %s (%s)", c.Subject, c.NotAfter, where))
			case c.ExpiresSoon:
				notes = append(notes, fmt.Sprintf("certificate for %s expires %s (%s)", c.Subject, c.NotAfter, where))
			}
			if c.SelfIssued {
				notes = append(notes, fmt.Sprintf("self-issued certificate for %s (%s)", c.Subject, where))
			}
		}
	}
	if len(notes) > 0 {
		b.WriteString("\nWhat stands out:\n")
		for _, n := range notes {
			b.WriteString("  " + n + "\n")
		}
	}

	b.WriteString("\nServices:\n")
	for _, s := range r.Services {
		kind := s.ServiceType
		if kind == "" {
			kind = "service"
		}
		fmt.Fprintf(&b, "  %s on %s (%s)", kind, strings.Join(s.Endpoints, ", "), strings.Join(s.Ports, ", "))
		if len(s.Software) > 0 {
			fmt.Fprintf(&b, "; %s", strings.Join(s.Software, "; "))
		}
		if len(s.Identified) > 0 {
			names := make([]string, 0, len(s.Identified))
			for _, p := range s.Identified {
				names = append(names, strings.TrimSpace(p.Product+" "+p.Version))
			}
			fmt.Fprintf(&b, "; runs %s", strings.Join(names, ", "))
		}
		if len(s.Products) > 0 {
			fmt.Fprintf(&b, "; stored products: %s", strings.Join(s.Products, ", "))
		}
		for _, c := range s.Certificates {
			fmt.Fprintf(&b, "; certificate %s", c.Subject)
			if c.Issuer != "" {
				fmt.Fprintf(&b, " from %s", c.Issuer)
			}
			if c.NotAfter != "" {
				fmt.Fprintf(&b, " until %s", c.NotAfter)
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("These are services stored by past probes, not a live scan. Identified software is read from " +
		"stored headers and banners, which software can hide or fake.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s); raise -max-assets or -max-reads to cover more.", r.Reason)
	}
	b.WriteString("\n")
	return b.String()
}
