// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var softwareLifecycleJSON = semantics.File("software_lifecycle.json")

type releaseLine struct {
	Series       string `json:"series"`
	EndOfSupport string `json:"end_of_support,omitempty"`
	end          time.Time
}

type productLifecycle struct {
	Product     string        `json:"product"`
	Source      string        `json:"source"`
	Unsupported []releaseLine `json:"unsupported"`
}

type softwareLifecycle struct {
	License  string             `json:"_license"`
	About    string             `json:"_about"`
	Products []productLifecycle `json:"products"`
}

// UnsupportedRelease is identified software in a release line its maker no
// longer supports.
type UnsupportedRelease struct {
	Product      string `json:"product"`
	Version      string `json:"version"`
	Series       string `json:"series"`
	EndOfSupport string `json:"end_of_support,omitempty"`
	Source       string `json:"source"`
}

// String describes the release for a report.
func (u UnsupportedRelease) String() string {
	s := fmt.Sprintf("%s %s (the %s line is no longer supported", u.Product, u.Version, u.Series)
	if u.EndOfSupport != "" {
		s += " since " + u.EndOfSupport
	}

	return s + ")"
}

var loadSoftwareLifecycle = sync.OnceValue(func() softwareLifecycle {
	var r softwareLifecycle
	if err := graph.DecodeStrict(softwareLifecycleJSON, &r); err != nil {
		panic("software_lifecycle.json: " + err.Error())
	}

	known := map[string]bool{}
	for _, f := range loadProductFingerprints().Fingerprints {
		known[f.Product] = true
	}
	for i := range r.Products {
		p := &r.Products[i]
		if !known[p.Product] || !strings.HasPrefix(p.Source, "https://") || len(p.Unsupported) == 0 {
			panic("software_lifecycle.json: " + p.Product + " must be a fingerprinted product with release " +
				"lines and an https source")
		}
		for j := range p.Unsupported {
			l := &p.Unsupported[j]
			if l.Series == "" {
				panic("software_lifecycle.json: " + p.Product + " has a release line without a series")
			}
			if l.EndOfSupport != "" {
				t, err := time.Parse("2006-01-02", l.EndOfSupport)
				if err != nil {
					panic("software_lifecycle.json: " + p.Product + " " + l.Series + ": " + err.Error())
				}

				l.end = t
			}
		}
	}

	return r
})

// lifecycleNow is the clock unsupported releases are judged by.
var lifecycleNow = time.Now

// unsupportedRelease reports whether identified software is in a release
// line its maker no longer supports.
func unsupportedRelease(p IdentifiedProduct) (UnsupportedRelease, bool) {
	if p.Version == "" {
		return UnsupportedRelease{}, false
	}

	now := lifecycleNow()
	for _, pl := range loadSoftwareLifecycle().Products {
		if pl.Product != p.Product {
			continue
		}
		for _, l := range pl.Unsupported {
			if !inSeries(p.Version, l.Series) || (!l.end.IsZero() && now.Before(l.end)) {
				continue
			}

			return UnsupportedRelease{Product: p.Product, Version: p.Version, Series: l.Series,
				EndOfSupport: l.EndOfSupport, Source: pl.Source}, true
		}
	}

	return UnsupportedRelease{}, false
}

// inSeries reports whether version is in a release line: equal to it, or
// beginning with it followed by anything other than a digit.
func inSeries(version, series string) bool {
	if !strings.HasPrefix(version, series) {
		return false
	}

	rest := version[len(series):]
	return rest == "" || rest[0] < '0' || rest[0] > '9'
}
