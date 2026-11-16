// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package confighelp describes the Amass configuration schema and validates
// and applies changes to a configuration file. It uses no language model,
// so the AI config assistant can be grounded in it without pulling a model
// into the description of the schema.
package confighelp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Field describes one configuration setting.
type Field struct {
	// Section is the catalog section the field belongs to (seed, scope,
	// options, transformations, datasources or ai).
	Section string `json:"section"`
	// Type is a short, human description of the value's shape.
	Type string `json:"type"`
	// Default is what applies when the field is unset, when that is
	// meaningful.
	Default string `json:"default,omitempty"`
	// Description says what the field does.
	Description string `json:"description"`
	// Example is a representative value.
	Example string `json:"example,omitempty"`
}

// Catalog is the described configuration schema.
type Catalog struct {
	Sections map[string]string `json:"sections"`
	Fields   map[string]Field  `json:"fields"`
}

var loadCatalog = sync.OnceValues(func() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(semantics.File("config_catalog.json"), &c); err != nil {
		return nil, fmt.Errorf("config_catalog.json: %w", err)
	}
	if len(c.Sections) == 0 || len(c.Fields) == 0 {
		return nil, fmt.Errorf("config_catalog.json: sections and fields are required")
	}
	for path, f := range c.Fields {
		if f.Section == "" || f.Description == "" || f.Type == "" {
			return nil, fmt.Errorf("config_catalog.json: %s needs a section, type and description", path)
		}
		if _, ok := c.Sections[f.Section]; !ok {
			return nil, fmt.Errorf("config_catalog.json: %s names an unknown section %q", path, f.Section)
		}
	}

	return &c, nil
})

// Load returns the configuration catalog, parsed once.
func Load() (*Catalog, error) {
	return loadCatalog()
}

// Lookup returns the field at an exact catalog path (such as
// "scope.domains"). A transformation key like "FQDN->DomainRecord" or
// "options.database" is matched; a per-item path like
// "transformations.ttl" is matched directly.
func (c *Catalog) Lookup(path string) (Field, bool) {
	f, ok := c.Fields[strings.TrimSpace(path)]
	return f, ok
}

// SectionFields returns the catalog fields of a section, sorted by path.
func (c *Catalog) SectionFields(section string) []string {
	var out []string
	for path, f := range c.Fields {
		if f.Section == section {
			out = append(out, path)
		}
	}

	sort.Strings(out)
	return out
}

// SectionNames returns the catalog's section names, sorted.
func (c *Catalog) SectionNames() []string {
	out := make([]string, 0, len(c.Sections))
	for name := range c.Sections {
		out = append(out, name)
	}

	sort.Strings(out)
	return out
}

// Paths returns every cataloged field path, sorted.
func (c *Catalog) Paths() []string {
	out := make([]string, 0, len(c.Fields))
	for path := range c.Fields {
		out = append(out, path)
	}

	sort.Strings(out)
	return out
}
