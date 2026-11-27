// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// Expansion policy. A transformation's reach says where an asset must stand
// for the transformation to run on it, so how far an enumeration widens is a
// matter of policy, set per transformation like its ttl:
//
//	scope:     the asset is within the scope the run was given (the seed
//	           and the scope section), not what the run admitted since
//	footprint: the asset is in scope, including what the run admitted
//	connected: the asset is linked to the footprint within hops
//	any:       every asset (the behavior before policies)
//
// A transformation without a reach takes its ALL transformation's, then
// transformations.default's, then footprint.
//
// A transformation's confidence above 100 (NeverAdmit) means nothing reached
// through it is admitted into scope: the scope never widens that way.
const (
	ReachScope     = "scope"
	ReachFootprint = "footprint"
	ReachConnected = "connected"
	ReachAny       = "any"
	// DefaultReachHops is how far a connected asset may be from the footprint
	// when hops is not set.
	DefaultReachHops = 1
	// MaxReachHops bounds hops.
	MaxReachHops = 5
	// DefaultReach applies where no transformation and no
	// transformations.default set one.
	DefaultReach = ReachFootprint
	// NeverAdmit is a confidence no evidence reaches: admission through a
	// transformation with it is refused.
	NeverAdmit = 101
)

// validateReach checks a transformation's reach and hops; where names the
// transformation in an error.
func (t *Transformation) validateReach(where string) error {
	if t == nil {
		return nil
	}
	t.Reach = strings.ToLower(strings.TrimSpace(t.Reach))
	switch t.Reach {
	case "", ReachScope, ReachFootprint, ReachConnected, ReachAny:
	default:
		return fmt.Errorf("%s: reach must be scope, footprint, connected or any, not %q", where, t.Reach)
	}
	if t.Hops < 0 || t.Hops > MaxReachHops {
		return fmt.Errorf("%s: hops must be 1..%d", where, MaxReachHops)
	}
	if t.Hops > 0 && t.Reach != ReachConnected {
		return fmt.Errorf("%s: hops applies only to reach: connected", where)
	}
	return nil
}

// TransformationReach returns the reach, and for connected the hops, that
// apply when an asset of type from is handed to a handler named to (a plugin)
// or producing any of tos. The most specific setting wins: a transformation
// naming the plugin, then one naming a target type (the narrowest reach of
// those that match), then from->ALL, then transformations.default, then
// any.
func (c *Config) TransformationReach(from, plugin string, tos ...string) (string, int) {
	from = strings.ToLower(from)
	targets := map[string]bool{}
	for _, t := range tos {
		targets[strings.ToLower(t)] = true
	}

	var named, typed, all *Transformation
	for _, t := range c.Transformations {
		if t == nil || t.From != from || t.Reach == "" {
			continue
		}
		switch {
		case plugin != "" && t.To == strings.ToLower(plugin):
			named = t
		case targets[t.To]:
			if typed == nil || reachRank(t.Reach) < reachRank(typed.Reach) {
				typed = t
			}
		case t.To == "all":
			all = t
		}
	}

	for _, t := range []*Transformation{named, typed, all, c.DefaultTransformations} {
		if t != nil && t.Reach != "" {
			return t.Reach, reachHops(t)
		}
	}
	return DefaultReach, 0
}

// HasExpansionPolicy reports whether the configuration sets a reach anywhere.
// Without one, DefaultReach applies everywhere, and Amass says so.
func (c *Config) HasExpansionPolicy() bool {
	if c.DefaultTransformations != nil && c.DefaultTransformations.Reach != "" {
		return true
	}
	for _, t := range c.Transformations {
		if t != nil && t.Reach != "" {
			return true
		}
	}
	return false
}

// NoPolicyWarning is what Amass says when a configuration sets no expansion
// policy.
const NoPolicyWarning = "no expansion policy is set (reach), so the footprint policy applies: transformations run " +
	"on the given scope and what it admits; see the example policies beside config.yaml to choose another"

// Widens reports whether anything can be admitted into scope: whether some
// transformation, or the defaults, admits at a confidence of 100 or below.
func (c *Config) Widens() bool {
	if c.DefaultTransformations == nil || c.DefaultTransformations.Confidence < NeverAdmit {
		return true
	}
	for _, t := range c.Transformations {
		if t != nil && t.Confidence > 0 && t.Confidence < NeverAdmit {
			return true
		}
	}
	return false
}

// ApplyStrictPolicy holds the run to the scope it was given: every
// transformation runs only on it, and nothing is admitted into it. An
// enumeration plan approved without expansion is run this way.
func (c *Config) ApplyStrictPolicy() {
	if c.DefaultTransformations == nil {
		c.DefaultTransformations = &Transformation{}
	}
	for _, t := range append([]*Transformation{c.DefaultTransformations}, mapValues(c.Transformations)...) {
		t.Reach, t.Hops, t.Confidence = ReachScope, 0, NeverAdmit
	}
}

func mapValues(m map[string]*Transformation) []*Transformation {
	out := make([]*Transformation, 0, len(m))
	for _, t := range m {
		if t != nil {
			out = append(out, t)
		}
	}
	return out
}

// MatchConfidence is a transformation's confidence used as the threshold
// for matching an asset against the scope. Above 100 the confidence only
// says that nothing is admitted (NeverAdmit); what is already in scope still
// matches it.
func MatchConfidence(conf int) int {
	return min(conf, 100)
}

// refuseRemovedSettings refuses the settings Amass v6 removed, so a
// configuration that relied on one is not silently run without it.
func (c *Config) refuseRemovedSettings(_ *Config) error {
	if _, ok := c.Options["rigid_boundaries"]; ok {
		return fmt.Errorf("options.rigid_boundaries was removed in Amass v6: set an expansion policy instead " +
			"(policy-strict.yaml in the examples beside config.yaml holds a run to its given scope)")
	}
	return nil
}

// reachRank orders reaches from the narrowest.
func reachRank(r string) int {
	switch r {
	case ReachScope:
		return 0
	case ReachFootprint:
		return 1
	case ReachConnected:
		return 2
	}
	return 3
}

func reachHops(t *Transformation) int {
	if t.Reach != ReachConnected {
		return 0
	}
	if t.Hops == 0 {
		return DefaultReachHops
	}
	return t.Hops
}
