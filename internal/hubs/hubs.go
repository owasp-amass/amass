// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package hubs tells, from the Asset Database's own data, when a shared value
// is held by too many assets to be evidence about any one of them: a
// provider's phone number, a CDN's certificate, a hosting company's name
// servers. For a kind of value (a Source: the values a relation label links
// to their holders, or the exact values of a tag or attribute), the
// database's histogram of how many holders each value has gives the typical
// count; a value whose count is a robust outlier (a modified z-score above k,
// in log scale) is a hub. k, the sample size and the floor come from
// internal/semantics/hubs.json. A database with too few such values says too
// little, and the caller's fixed limit applies.
package hubs

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
)

// Source names a kind of shared value whose holder counts the database can
// histogram: with Label set, the values a relation label links to their
// holders, which point at them ("in") or are listed by them ("out"), only
// the values of AssetType whose attribute Property equals Value when Value
// is set (the fingerprint Identifiers of one id_type); otherwise, with
// AssetType and Property set, the exact values of that tag on assets of the
// type, only those starting with one of Prefixes when there are any, or of
// that stored attribute when Attribute is set.
type Source struct {
	Label     string
	Direction string
	AssetType string
	Property  string
	Value     string
	Prefixes  []string
	Attribute bool
}

// Key names the source in the journal and in the leases.
func (s Source) Key() string {
	if s.Label != "" {
		key := strings.ToLower(strings.TrimSpace(s.Label)) + "|" + s.Direction
		if s.Value != "" {
			key += "|" + strings.ToLower(s.AssetType) + "." + s.Property + "=" + s.Value
		}
		return key
	}
	if s.Attribute {
		return "attr:" + strings.ToLower(s.AssetType) + "|" + s.Property
	}
	prefixes := make([]string, len(s.Prefixes))
	for i, p := range s.Prefixes {
		prefixes[i] = strings.ToLower(p)
	}
	sort.Strings(prefixes)
	return "tag:" + strings.ToLower(s.AssetType) + "|" + s.Property + "|" + strings.Join(prefixes, ",")
}

// Threshold is what the database says about one kind of shared value (its
// Source's key): how many values there are, the median and spread of their
// holder counts in log scale, and the most holders a value may have before
// it is a hub.
type Threshold struct {
	Key    string    `json:"key"`
	Values int64     `json:"values"`
	Median float64   `json:"median"`
	Spread float64   `json:"spread"`
	Limit  int       `json:"limit"`
	At     time.Time `json:"at"`
}

// For returns the most holders a value may have, and whether the database
// decided it: the derived limit (at least the floor) when the database has
// the minimum sample of values of the kind and their counts vary, otherwise
// fallback.
func (t Threshold) For(fallback int) (int, bool) {
	c := semantics.HubsCatalog()
	if t.Values < c.MinSample || t.Limit <= 0 {
		return fallback, false
	}
	return max(c.Floor, t.Limit), true
}

// point is one degree of a histogram in log scale, with how many values
// have it.
type point struct {
	x float64
	n int64
}

// Derive computes the threshold of the values of the source named key from
// their histogram: holders of a value -> values with that many holders.
func Derive(key string, h dbt.DegreeHistogram) Threshold {
	t := Threshold{Key: key, At: time.Now()}
	var pts []point
	for d, n := range h {
		if d > 0 && n > 0 {
			pts = append(pts, point{x: math.Log(float64(d)), n: n})
			t.Values += n
		}
	}
	if t.Values == 0 {
		return t
	}

	t.Median = weightedMedian(pts, t.Values)
	devs := make([]point, len(pts))
	var sum float64
	for i, p := range pts {
		devs[i] = point{x: math.Abs(p.x - t.Median), n: p.n}
		sum += devs[i].x * float64(p.n)
	}
	// sigma from the median absolute deviation, or, when more than half the
	// values share one count, from the mean absolute deviation
	if mad := weightedMedian(devs, t.Values); mad > 0 {
		t.Spread = mad / 0.6745
	} else {
		t.Spread = 1.253314 * sum / float64(t.Values)
	}
	if t.Spread > 0 {
		t.Limit = int(math.Floor(math.Exp(t.Median + semantics.HubsCatalog().K*t.Spread)))
	}
	return t
}

// weightedMedian is the median of the points' x, each counted n times; total
// is the sum of n.
func weightedMedian(pts []point, total int64) float64 {
	sort.Slice(pts, func(i, j int) bool { return pts[i].x < pts[j].x })
	half := (total + 1) / 2
	var seen int64
	for _, p := range pts {
		if seen += p.n; seen >= half {
			return p.x
		}
	}
	return pts[len(pts)-1].x
}
