// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var webApplicationsJSON = semantics.File("web_applications.json")

type webVersionRule struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Path    string `json:"path"`
	Query   string `json:"query"`
	Source  string `json:"source"`
	re      *regexp.Regexp
}

type webComponentRule struct {
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Query string `json:"query,omitempty"`
	re    *regexp.Regexp
}

type webApplicationRule struct {
	Product    string             `json:"product"`
	Vendor     string             `json:"vendor"`
	Path       string             `json:"path"`
	Source     string             `json:"source"`
	Versions   []webVersionRule   `json:"versions,omitempty"`
	Components []webComponentRule `json:"components,omitempty"`
	re         *regexp.Regexp
}

type webApplicationRules struct {
	License      string               `json:"_license"`
	About        string               `json:"_about"`
	URLTypes     []string             `json:"url_types"`
	URLField     string               `json:"url_field"`
	Applications []webApplicationRule `json:"applications"`
}

func compileFold(pattern string) (*regexp.Regexp, error) { return regexp.Compile("(?i)" + pattern) }

func (r *webApplicationRules) validate() error {
	if len(r.URLTypes) == 0 || r.URLField == "" {
		return fmt.Errorf("url_types and url_field are required")
	}

	var err error
	for i := range r.Applications {
		a := &r.Applications[i]
		if a.Product == "" || !strings.HasPrefix(a.Source, "https://") {
			return fmt.Errorf("application %d: product and a documentation source are required", i)
		}
		if a.re, err = compileFold(a.Path); err != nil {
			return fmt.Errorf("application %s: %w", a.Product, err)
		}
		for j := range a.Versions {
			v := &a.Versions[j]
			if v.Product == "" || v.Query == "" || !strings.HasPrefix(v.Source, "https://") {
				return fmt.Errorf("application %s: a version rule needs a product, query and source", a.Product)
			}
			if v.re, err = compileFold(v.Path); err != nil {
				return fmt.Errorf("application %s: %w", a.Product, err)
			}
		}
		for j := range a.Components {
			c := &a.Components[j]
			if c.Kind == "" {
				return fmt.Errorf("application %s: a component rule needs a kind", a.Product)
			}
			if c.re, err = compileFold(c.Path); err != nil {
				return fmt.Errorf("application %s: %w", a.Product, err)
			}
			if c.re.NumSubexp() < 1 {
				return fmt.Errorf("application %s: a component path captures the component's name", a.Product)
			}
		}
	}

	return nil
}

var loadWebApplicationRules = sync.OnceValue(func() webApplicationRules {
	var r webApplicationRules
	if err := graph.DecodeStrict(webApplicationsJSON, &r); err != nil {
		panic("web_applications.json: " + err.Error())
	}
	if err := r.validate(); err != nil {
		panic("web_applications.json: " + err.Error())
	}

	return r
})

// WebComponent is an add-on of a web application, such as a plugin or a
// theme. AssetVersions are the versions written in its asset URLs, which
// the add-on chooses, so they are not confirmed releases.
type WebComponent struct {
	Kind          string   `json:"kind"`
	Name          string   `json:"name"`
	AssetVersions []string `json:"asset_versions,omitempty"`
}

// WebApplication is a web application recognized on a site from its
// stored URLs. Identified holds the releases its files carry; it is
// computed, not stored.
type WebApplication struct {
	Site       string              `json:"site"`
	Product    string              `json:"product"`
	Vendor     string              `json:"vendor,omitempty"`
	Source     string              `json:"source"`
	URLs       int                 `json:"urls"`
	Identified []IdentifiedProduct `json:"identified,omitempty"`
	Components []WebComponent      `json:"components,omitempty"`
}

// identifyWebApplications recognizes web applications on the sites of the
// stored URLs among assets.
func identifyWebApplications(assets []graph.Asset) []WebApplication {
	rules := loadWebApplicationRules()
	apps := map[string]*WebApplication{}
	components := map[string]map[string]*WebComponent{}
	for _, a := range assets {
		if !slices.Contains(rules.URLTypes, a.Type) {
			continue
		}

		raw := graph.ContentString(a, rules.URLField)
		if raw == "" {
			raw = a.Key
		}

		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}

		site := strings.ToLower(u.Scheme + "://" + u.Host)
		for _, rule := range rules.Applications {
			if !rule.re.MatchString(u.Path) {
				continue
			}

			key := site + "|" + rule.Product
			app, ok := apps[key]
			if !ok {
				app = &WebApplication{Site: site, Product: rule.Product, Vendor: rule.Vendor, Source: rule.Source}
				apps[key] = app
				components[key] = map[string]*WebComponent{}
			}

			app.URLs++
			for _, v := range rule.Versions {
				ver := u.Query().Get(v.Query)
				if ver == "" || !v.re.MatchString(u.Path) {
					continue
				}

				p := IdentifiedProduct{
					Product:  v.Product,
					Vendor:   v.Vendor,
					Version:  ver,
					Evidence: raw,
					Source:   v.Source,
				}
				if !slices.ContainsFunc(app.Identified, func(o IdentifiedProduct) bool {
					return o.Product == p.Product && o.Version == p.Version
				}) {
					app.Identified = append(app.Identified, p)
				}
			}
			for _, c := range rule.Components {
				m := c.re.FindStringSubmatch(u.Path)
				if m == nil || m[1] == "" {
					continue
				}

				ck := c.Kind + "|" + strings.ToLower(m[1])
				comp, ok := components[key][ck]
				if !ok {
					comp = &WebComponent{Kind: c.Kind, Name: strings.ToLower(m[1])}
					components[key][ck] = comp
				}
				if c.Query != "" {
					if ver := u.Query().Get(c.Query); ver != "" {
						graph.AddUnique(&comp.AssetVersions, ver)
					}
				}
			}
		}
	}

	out := make([]WebApplication, 0, len(apps))
	for key, app := range apps {
		for _, c := range components[key] {
			sort.Strings(c.AssetVersions)
			app.Components = append(app.Components, *c)
		}

		sort.Slice(app.Components, func(i, j int) bool {
			a, b := app.Components[i], app.Components[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}

			return a.Name < b.Name
		})
		sort.Slice(app.Identified, func(i, j int) bool {
			a, b := app.Identified[i], app.Identified[j]
			if a.Product != b.Product {
				return a.Product < b.Product
			}

			return a.Version < b.Version
		})
		out = append(out, *app)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Site != out[j].Site {
			return out[i].Site < out[j].Site
		}

		return out[i].Product < out[j].Product
	})
	return out
}

// String names the application with the releases its files carry.
func (a WebApplication) String() string {
	var vers []string
	for _, p := range a.Identified {
		if p.Product == a.Product {
			vers = append(vers, p.Version)
		}
	}

	name := a.Product
	if len(vers) > 0 {
		name += " " + strings.Join(vers, "/")
	}

	return name
}

// webComponentsShown is how many components a site's line names.
const webComponentsShown = 12

// writeWebApplications adds the recognized web applications to a report.
func writeWebApplications(b *strings.Builder, apps []WebApplication) {
	if len(apps) == 0 {
		return
	}

	b.WriteString("\nWeb applications (from stored URLs):\n")
	for _, a := range apps {
		fmt.Fprintf(b, "  %s on %s (%d URLs)", a.String(), a.Site, a.URLs)
		for _, p := range a.Identified {
			if p.Product != a.Product {
				fmt.Fprintf(b, "; bundles %s %s", p.Product, p.Version)
			}
		}
		if len(a.Components) > 0 {
			names := make([]string, 0, min(len(a.Components), webComponentsShown))
			for i, c := range a.Components {
				if i == webComponentsShown {
					names = append(names, fmt.Sprintf("and %d more", len(a.Components)-i))
					break
				}

				name := c.Kind + " " + c.Name
				if len(c.AssetVersions) > 0 {
					name += " (asset ver " + strings.Join(c.AssetVersions, "/") + ")"
				}

				names = append(names, name)
			}

			fmt.Fprintf(b, "; %s", strings.Join(names, ", "))
		}

		b.WriteString("\n")
	}

	b.WriteString("Add-on versions are those written in their asset URLs, which each add-on chooses; they are " +
		"not confirmed releases.\n")
}
