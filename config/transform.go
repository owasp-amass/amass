// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	oam "github.com/owasp-amass/open-asset-model"
)

// Transformation represents an individual transofmration with optional priority & confidence.
type Transformation struct {
	From       string   `yaml:"-" json:"-"`
	To         string   `yaml:"-" json:"-"`
	Priority   int      `yaml:"priority,omitempty" json:"priority,omitempty"`
	Confidence int      `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Exclude    []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	TTL        int      `yaml:"ttl,omitempty" json:"ttl,omitempty"`
	// Reach and Hops are the transformation's expansion policy (reach.go):
	// where an asset must stand for the transformation to run on it.
	Reach string `yaml:"reach,omitempty" json:"reach,omitempty"`
	Hops  int    `yaml:"hops,omitempty" json:"hops,omitempty"`
}

// Matches represents a collection of transform matches.
type Matches struct {
	lock sync.Mutex
	to   map[string]match
}

// match is what a transformation match carries.
type match struct {
	ttl        int
	confidence int
}

// loadTransformSettings processes the Transformations map from the configuration,
// assigning structured data to each Transformation based on its key.
// Each key is parsed into 'From' and 'To' segments, representing the origin and target
// of the transformation, respectively, which are then stored in the corresponding Transformation struct.
func (c *Config) loadTransformSettings(cfg *Config) error {
	// The defaults first, so no other transformation is read as one.
	if err := c.loadDefaultTransformation(); err != nil {
		return err
	}
	// Split every key into its 'From' and 'To' first, so each type's ALL
	// transformation is known before the others take its values.
	alls := map[string]*Transformation{}
	for key, transformation := range c.Transformations {
		// Initialize transformation if nil
		if transformation == nil {
			transformation = &Transformation{}      // default struct
			c.Transformations[key] = transformation // assign it back to the map
		}
		// Spit the key into 'From' and 'To' components.
		if err := transformation.Split(key); err != nil {
			return fmt.Errorf("error when splitting the key: %w", err)
		}
		if transformation.To == "all" {
			alls[transformation.From] = transformation
		}
	}
	// An ALL transformation's unset ttl and confidence are the defaults'.
	for _, all := range alls {
		all.fill(c.DefaultTransformations)
	}
	// Iterate through each transformation rule defined in the configuration.
	for key, transformation := range c.Transformations {
		// A transformation's unset ttl and confidence are its ALL
		// transformation's, then the defaults'.
		if all, ok := alls[transformation.From]; ok && transformation != all {
			transformation.fill(all)
		}
		transformation.fill(c.DefaultTransformations)

		err := transformation.Validate(c)
		if err != nil {
			return err
		}
		if err := transformation.validateReach(key); err != nil {
			return err
		}
	}
	// If the loop completes with no conflicts, the function returns nil, indicating success.
	return nil
}

// fill sets the transformation's unset ttl and confidence from from's.
func (t *Transformation) fill(from *Transformation) {
	if from == nil {
		return
	}
	if t.Confidence == 0 {
		t.Confidence = from.Confidence
	}
	if t.TTL == 0 {
		t.TTL = from.TTL
	}
}

// DefaultTransformationKey is the transformations entry whose values every
// transformation that does not set its own takes: ttl, confidence, priority,
// and the expansion policy's reach and hops.
const DefaultTransformationKey = "default"

// loadDefaultTransformation takes transformations.default out of the
// transformations, into DefaultTransformations. The values once set under
// options are refused, so a policy is never silently lost.
func (c *Config) loadDefaultTransformation() error {
	if _, ok := c.Options["default_transform_values"]; ok {
		return errors.New("options.default_transform_values moved to transformations.default: move it there")
	}

	for key, t := range c.Transformations {
		if !strings.EqualFold(key, DefaultTransformationKey) {
			continue
		}
		delete(c.Transformations, key)
		if t == nil {
			continue
		}
		if len(t.Exclude) > 0 {
			return errors.New("transformations.default: exclude applies to a FROM->ALL transformation")
		}

		if c.DefaultTransformations == nil {
			c.DefaultTransformations = &Transformation{}
		}
		d := c.DefaultTransformations
		if t.TTL != 0 {
			d.TTL = t.TTL
		}
		if t.Confidence != 0 {
			d.Confidence = t.Confidence
		}
		if t.Priority != 0 {
			d.Priority = t.Priority
		}
		if t.Reach != "" {
			d.Reach, d.Hops = t.Reach, t.Hops
		}
		if err := d.validateReach("transformations." + DefaultTransformationKey); err != nil {
			return err
		}
	}
	return nil
}

// Split splits the key into 'From' and 'To' components, expecting a "->" delimiter.
// Requires a non-nil Transformation pointer and a valid key format. Example: FQDN->IPaddress.
func (t *Transformation) Split(key string) error {
	if t.From != "" && t.To != "" {
		t.From = strings.ToLower(t.From)
		t.To = strings.ToLower(t.To)
		return nil // Already split
	}
	// Split the key into 'From' and 'To' components, expecting a "->" delimiter.
	parts := strings.Split(key, "->")
	if len(parts) != 2 {
		return fmt.Errorf("invalid key delimiter: %s", key)
	}
	// Assign the 'From' and 'To' values to the Transformation struct.
	t.From = strings.ToLower(parts[0])
	t.To = strings.ToLower(parts[1])
	return nil
}

// Validate checks the validity of a given transformation with respect to OAM &
// previously registered transformations. The function ensures OAM compliance & that there are no conflicts
// between transformations with 'none' (indicating no action) and other valid transformations
// for the same 'From' type.
func (t *Transformation) Validate(c *Config) error {
	if c.fromWithNone == nil {
		c.fromWithNone = make(map[string]bool)
	}
	if c.fromWithValid == nil {
		c.fromWithValid = make(map[string]bool)
	}
	tfound := false
	ffound := false
	// Check if "From" and "To" is OAM compliant
	for _, a := range oam.AssetList {
		a := strings.ToLower(string(a))
		if t.From == a {
			ffound = true
		}
		if t.To == a || t.To == "none" || t.To == "all" {
			tfound = true
		}
		// Used to prevent unnecessary iterations
		if tfound && ffound {
			break
		}
	}

	if !ffound {
		return fmt.Errorf("invalid 'From' type: %s does not comply with OAM", t.From)
	}
	// Check for a 'none' transformation, which indicates that no further processing is required for this 'From' type.
	if t.To == "none" {
		// Conflict arises if there's already a valid transformation for this 'From'.
		if c.fromWithValid[t.From] {
			return fmt.Errorf("invalid config: 'none' specified after a valid transformation for 'From' type: %s. 'None' should be the only transformation", t.From)
		}
		c.fromWithNone[t.From] = true
	} else { // For other valid transformations.
		// Conflict arises if a 'none' transformation is already registered for this 'From'.
		if c.fromWithNone[t.From] {
			return fmt.Errorf("invalid config: valid transformation specified after 'none' for 'From' type: %s. 'None' should be the only transformation", t.From)
		}
		// Mark this 'From' as having a valid transformation.
		c.fromWithValid[t.From] = true
	}

	return nil
}

// CheckTransformations checks if the given 'From' type has a valid transformation to any of the given 'To' types.
// A transformation naming a 'To' type (or a data source) applies to it, even one the ALL transformation
// excludes; otherwise ALL applies unless it excludes the 'To'. A named transformation's unset ttl or
// confidence is its ALL transformation's, so the result is the same whatever order the transformations
// are read in.
func (c *Config) CheckTransformations(from string, tos ...string) (*Matches, error) {
	lower := strings.ToLower(from)
	var all *Transformation
	named := map[string]*Transformation{}
	for _, transform := range c.Transformations {
		if transform == nil || lower != transform.From {
			continue
		}
		if transform.To == "all" {
			all = transform
		} else {
			named[transform.To] = transform
		}
	}

	excludes := make(map[string]bool)
	if all != nil {
		for _, e := range all.Exclude {
			excludes[strings.ToLower(e)] = true
		}
	}

	results := &Matches{to: make(map[string]match)}
	for _, v := range tos {
		to := strings.ToLower(v)
		if t, ok := named[to]; ok {
			m := match{ttl: t.checkTTL(to, c), confidence: t.Confidence}
			if all != nil {
				if m.ttl == 0 {
					m.ttl = all.checkTTL(to, c)
				}
				if m.confidence == 0 {
					m.confidence = all.Confidence
				}
			}
			results.to[to] = m
		} else if all != nil && !excludes[to] {
			results.to[to] = match{ttl: all.checkTTL(to, c), confidence: all.Confidence}
		}
	}

	if len(results.to) == 0 {
		return nil, fmt.Errorf("zero transformation matches in the session config")
	}
	return results, nil
}

// checkTTl checks the TTL value for the given 'To' type in the given Config.
// if the 'To' is a data source, it will return the TTL value from the data source config.
// otherwise, it will return the default TTL value from the transformation config.
func (t *Transformation) checkTTL(to string, c *Config) int {
	if c != nil {
		if c.DataSrcConfigs != nil {
			ds := c.GetDataSourceConfig(to)
			if ds != nil && ds.TTL > 0 {
				return ds.TTL
			}
		}
	}
	return t.TTL
}

// IsMatch checks if a valid transformation to the given 'To' type is present.
func (m *Matches) IsMatch(to string) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, found := m.to[strings.ToLower(to)]
	return found
}

// Len returns the number of matches in the result set.
func (m *Matches) Len() int {
	m.lock.Lock()
	defer m.lock.Unlock()

	return len(m.to)
}

// TTL returns the ttl for a given 'To' type in the Matches struct.
// If the 'To' type is not found, the function returns -1.
func (m *Matches) TTL(to string) int {
	if m.IsMatch(to) {
		return m.to[strings.ToLower(to)].ttl
	}
	return -1
}

// Confidence returns the confidence for a given 'To' type in the Matches struct.
// If the 'To' type is not found, the function returns -1.
func (m *Matches) Confidence(to string) int {
	if m.IsMatch(to) {
		return m.to[strings.ToLower(to)].confidence
	}
	return -1
}
