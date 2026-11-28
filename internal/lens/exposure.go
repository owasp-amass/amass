// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensExposure asks what a domain or organization exposes to the internet
// that deserves attention.
const LensExposure = "exposure"

var exposureLens = SubjectLens{
	Name:    LensExposure,
	Command: "exposure",
	Description: "Summarize what a domain or organization exposes that deserves attention: remote access, " +
		"databases, file sharing, management interfaces, login pages, unusual ports, bad certificates. Read-only",
	Examples: []string{"What does <domain> expose that it shouldn't?", "Does <organization> expose databases or RDP?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindExposure(ctx, g, schema, root, opts.Limits)
	},
}

// Exposure classes computed from the services lens rather than exposure.json.
const (
	ExposureUnusualPort  = "unusual_ports"
	ExposureBadCert      = "certificate_problems"
	ExposureUnsupported  = "unsupported_software"
	ExposurePublicBucket = "public_bucket"
	ExposureReputation   = "reputation_listed"
)

// ExposureClass is one kind of exposure and what falls in it.
type ExposureClass struct {
	Name      string   `json:"name"`
	Title     string   `json:"title"`
	Rationale string   `json:"rationale"`
	Count     int      `json:"count"`
	Examples  []string `json:"examples"`
}

// ExposureReport is the result of the exposure lens.
type ExposureReport struct {
	lensBase
	Services int             `json:"services"`
	URLs     int             `json:"urls"`
	Classes  []ExposureClass `json:"classes"`
}

var exposureJSON = semantics.File("exposure.json")

type exposureClassRule struct {
	Name         string   `json:"name"`
	Title        string   `json:"title"`
	Ports        []int    `json:"ports"`
	ServiceTypes []string `json:"service_types"`
	URLPatterns  []string `json:"url_patterns"`
	URLFields    []string `json:"url_fields"`
	TitlePattern []string `json:"title_patterns"`
	TXTPatterns  []string `json:"txt_patterns"`
	Rationale    string   `json:"rationale"`
	Source       string   `json:"source"`
	res          []*regexp.Regexp
	titles       []*regexp.Regexp
	txts         []*regexp.Regexp
}

type exposureRules struct {
	License    string              `json:"_license"`
	About      string              `json:"_about"`
	PortSource string              `json:"port_source"`
	URLTypes   []string            `json:"url_types"`
	URLField   string              `json:"url_field"`
	Classes    []exposureClassRule `json:"classes"`
}

var loadExposureRules = sync.OnceValue(func() exposureRules {
	var r exposureRules
	if err := graph.DecodeStrict(exposureJSON, &r); err != nil {
		panic("exposure.json: " + err.Error())
	}
	for i := range r.Classes {
		c := &r.Classes[i]
		if c.Name == "" || c.Title == "" || c.Rationale == "" {
			panic("exposure.json: every class needs a name, title and rationale")
		}
		for _, p := range c.URLPatterns {
			c.res = append(c.res, regexp.MustCompile(p))
		}
		for _, p := range c.TitlePattern {
			c.titles = append(c.titles, regexp.MustCompile(p))
		}
		for _, p := range c.TXTPatterns {
			c.txts = append(c.txts, regexp.MustCompile(p))
		}
	}

	return r
})

const exposureExamples = 5

// FindExposure reports what a domain or organization exposes that
// deserves attention, grouped by kind: the services the services lens
// finds, classed by port, type and page title, its login and administration
// URLs and URLs with a password in them (masked), and the unusual ports and
// certificate problems the services lens reports. It reads only.
func FindExposure(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (ExposureReport, error) {
	// The lenses this one builds on walk the same footprint; read it once.
	g = graph.Cached(g)
	var out ExposureReport
	services, err := FindServices(ctx, g, schema, root, limits)
	if err != nil {
		return out, err
	}

	rules := loadExposureRules()
	classes := make([]ExposureClass, 0, len(rules.Classes)+2)
	for _, c := range rules.Classes {
		classes = append(classes, ExposureClass{Name: c.Name, Title: c.Title, Rationale: c.Rationale})
	}

	unusual := ExposureClass{Name: ExposureUnusualPort, Title: "Services on unusual ports",
		Rationale: "services moved to unusual ports are often forgotten and unmonitored"}
	certs := ExposureClass{Name: ExposureBadCert, Title: "Services with certificate problems",
		Rationale: "expired and self-issued certificates train users to click through warnings"}
	unsupported := ExposureClass{Name: ExposureUnsupported, Title: "Software its maker no longer supports",
		Rationale: "release lines past their end of support get no security fixes; check whether the distribution " +
			"backports them before treating the version as vulnerable"}
	publicBucket := ExposureClass{Name: ExposurePublicBucket, Title: "World-readable storage buckets",
		Rationale: "a publicly listable object-storage bucket exposes its files to anyone on the internet"}
	listed := ExposureClass{Name: ExposureReputation, Title: "Addresses on reputation feeds",
		Rationale: "an address or netblock a blocklist names is often refused by mail servers and firewalls, and " +
			"can mean a host was compromised, a range was hijacked or a Tor exit runs there"}
	leaked := ExposureClass{Name: ExposureLeaked, Title: "Leaked credentials",
		Rationale: "a key or token the footprint serves or publishes can be used by anyone who finds it; " +
			"rotate it, then find out how it was published (amass secrets found <reference> shows the value)"}
	note := func(c *ExposureClass, example string) {
		c.Count++
		if len(c.Examples) < exposureExamples {
			graph.AddUnique(&c.Examples, example)
		}
	}

	// URLs and page titles come from the controlled footprint the services
	// lens walked.
	s, err := newScope(ctx, g, schema, root, limits, "exposure")
	if err != nil {
		return out, err
	}
	for _, svc := range services.Services {
		label := serviceLabel(svc)
		i := classOfService(rules, svc)
		if i < 0 {
			var title string
			i, title = s.classOfTitle(rules, svc.Service)
			if i >= 0 {
				label += fmt.Sprintf(" %q", title)
			}
		}
		if i >= 0 {
			note(&classes[i], label)
		}
		if len(svc.UnusualPorts) > 0 {
			note(&unusual, label)
		}
		for _, u := range svc.Unsupported {
			note(&unsupported, fmt.Sprintf("%s: %s", strings.Join(svc.Endpoints[:min(2, len(svc.Endpoints))], ", "), u))
		}
		for _, c := range svc.Certificates {
			switch {
			case c.Expired:
				note(&certs, fmt.Sprintf("%s (expired certificate for %s)", label, c.Subject))
			case c.SelfIssued:
				note(&certs, fmt.Sprintf("%s (self-issued certificate for %s)", label, c.Subject))
			}
		}
	}

	readTXT := slices.ContainsFunc(rules.Classes, func(c exposureClassRule) bool { return len(c.txts) > 0 })
	for _, id := range s.order {
		a := s.owned[id]
		if a.Type == "FQDN" && readTXT {
			if err := s.classifyTXT(rules, a, func(i int, example string) { note(&classes[i], example) }); err != nil {
				return out, err
			}
		}
		if a.Type == "FQDN" && !s.spent() {
			// A footprint name is exposed when it is, or aliases to, a bucket host
			// whose stored bucket a probe found world-readable. Bucket hosts
			// usually appear as CNAME targets (resolve the alias, as the dangling
			// lens does), but one can also be a footprint member in its own right.
			host, ok, berr := bucketHost(s.w, a)
			if berr != nil {
				return out, berr
			}
			if ok {
				sb, found, berr := storedBucket(s.w, host)
				if berr != nil {
					return out, berr
				}
				if found && bucketExists(sb) && bucketPublic(sb) {
					note(&publicBucket, graph.FQDNName(a))
				}
			}
		}
		if !slices.Contains(rules.URLTypes, a.Type) {
			continue
		}

		out.URLs++
		u := graph.ContentString(a, rules.URLField)
		if u == "" {
			u = a.Key
		}
		for i, c := range rules.Classes {
			if slices.ContainsFunc(c.URLFields, func(f string) bool { return graph.ContentString(a, f) != "" }) ||
				slices.ContainsFunc(c.res, func(re *regexp.Regexp) bool { return re.MatchString(u) }) {
				note(&classes[i], maskURL(u))
				break
			}
		}
	}

	if err := reputationListed(ctx, g, s.owned, func(example string) { note(&listed, example) }); err != nil {
		return out, err
	}

	if err := leakedCredentials(ctx, g, s.owned, func(example string) { note(&leaked, example) }); err != nil {
		return out, err
	}

	out.lensBase = s.base()
	if services.Truncated {
		out.Truncated, out.Reason = true, services.Reason
	}

	out.Services = len(services.Services)
	for _, c := range append(append([]ExposureClass{leaked}, classes...), unsupported, unusual, certs,
		publicBucket, listed) {
		if c.Count > 0 {
			out.Classes = append(out.Classes, c)
		}
	}

	return out, nil
}

// reputationListed notes each address and netblock of the footprint a
// reputation feed lists (engine plugin reputation), read with one value
// search per feed and type. A repository without value searches gives none.
func reputationListed(ctx context.Context, g graph.Graph, owned map[string]graph.Asset,
	note func(string)) error {
	vs, ok := g.(ValueSearcher)
	if !ok {
		return nil
	}
	titles := semantics.ReputationFeedTitles()
	names := make([]string, 0, len(titles))
	for name := range titles {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		for _, typ := range []string{"IPAddress", "Netblock"} {
			found, _, err := vs.FindByTagValue(ctx, typ, semantics.ReputationListingProperty, name, false, 0)
			if errors.Is(err, ErrValueSearchUnsupported) {
				return nil
			} else if err != nil {
				return err
			}
			for _, a := range found {
				if _, mine := owned[a.ID]; mine {
					note(fmt.Sprintf("%s (%s)", graph.AssetLabel(a), titles[name]))
				}
			}
		}
	}
	return nil
}

// classOfService returns the index of the first class a service falls in,
// or -1.
func classOfService(rules exposureRules, svc ExposedService) int {
	for i, c := range rules.Classes {
		if slices.ContainsFunc(c.ServiceTypes, func(t string) bool { return strings.EqualFold(t, svc.ServiceType) }) {
			return i
		}
		for _, p := range svc.Ports {
			n, err := strconv.Atoi(strings.SplitN(p, "/", 2)[0])
			if err == nil && slices.Contains(c.Ports, n) {
				return i
			}
		}
	}

	return -1
}

// classOfTitle returns the index of the first class whose title patterns match
// the page title the probe stored for svc, and the title, or -1. The title is
// taken from the service's saved page body, so it needs no extra read and does
// not depend on how the title is stored for correlation.
func (s *scope) classOfTitle(rules exposureRules, svc graph.Asset) (int, string) {
	if !slices.ContainsFunc(rules.Classes, func(c exposureClassRule) bool {
		return len(c.titles) > 0
	}) {
		return -1, ""
	}

	title := fingerprint.PageTitle(graph.ContentString(svc, "output"))
	if title == "" {
		return -1, ""
	}
	for i, c := range rules.Classes {
		if slices.ContainsFunc(c.titles, func(re *regexp.Regexp) bool { return re.MatchString(title) }) {
			return i, title
		}
	}

	return -1, ""
}

// classifyTXT notes the TXT records stored for name that a class's TXT
// patterns match, while reads remain.
func (s *scope) classifyTXT(rules exposureRules, name graph.Asset, note func(int, string)) error {
	if s.spent() {
		return nil
	}

	s.report.Reads++
	records, err := graph.TXTValues(s.w.ctx, s.w.graph, name.ID)
	if err != nil {
		return err
	}
	for _, rec := range records {
		for i, c := range rules.Classes {
			if slices.ContainsFunc(c.txts, func(re *regexp.Regexp) bool { return re.MatchString(rec) }) {
				note(i, fmt.Sprintf("%s: %s", graph.FQDNName(name), rec))
				break
			}
		}
	}

	return nil
}

// maskURL hides a password written into a URL.
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if at := strings.LastIndex(raw, "@"); at >= 0 {
			if scheme := strings.Index(raw, "://"); scheme >= 0 && scheme < at {
				return raw[:scheme+3] + "xxxxx" + raw[at:]
			}
		}

		return raw
	}

	return u.Redacted()
}

func serviceLabel(svc ExposedService) string {
	label := strings.Join(svc.Endpoints[:min(2, len(svc.Endpoints))], ", ")
	if len(svc.Ports) > 0 {
		label += " " + strings.Join(svc.Ports, ",")
	}
	if svc.ServiceType != "" {
		label += " " + svc.ServiceType
	}
	if len(svc.Identified) > 0 {
		label += " (" + strings.TrimSpace(svc.Identified[0].Product+" "+svc.Identified[0].Version) + ")"
	}

	return label
}

// Text implements Report.
func (r ExposureReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Exposure of %s: %d service(s) and %d URL(s) from %d controlled asset(s).\n", subject,
		r.Services, r.URLs, r.Footprint)
	b.WriteString(r.summarizedNote())
	if len(r.Classes) == 0 {
		b.WriteString("Nothing stored falls in a class that deserves attention.\n")
	}
	for _, c := range r.Classes {
		fmt.Fprintf(&b, "\n%s (%d): %s.\n", c.Title, c.Count, c.Rationale)
		for _, e := range c.Examples {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}

	b.WriteString("\nThese come from past probes and enumerations, not a live scan; the dangling and certificates " +
		"lenses report more." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r ExposureReport) Facts() []string {
	var out []string
	for _, c := range r.Classes {
		for _, e := range c.Examples {
			out = append(out, c.Name+" "+e)
		}
	}

	return out
}
