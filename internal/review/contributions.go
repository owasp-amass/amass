// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// ContributionPrefix starts every contribution ID.
const ContributionPrefix = "ctb-"

// MaxContributedItems bounds the items one contribution (one approval)
// holds.
const MaxContributedItems = 50

// The kinds of contributed item.
const (
	ContributedAsset    = "asset"
	ContributedRelation = "relation"
	ContributedProperty = "property"
)

// IsContribution reports whether id is a contribution's.
func IsContribution(id string) bool { return strings.HasPrefix(id, ContributionPrefix) }

// ContributionSource is the source an assistant's contributions are recorded
// under: amass-ai:<client>, unique per client and distinct from the engine's
// sources and from amass-ai's own decisions.
func ContributionSource(client string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(client)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	name := b.String()
	if name == "" {
		name = "assistant"
	}
	return graph.ContributionSourcePrefix + name
}

// AssetRef names an asset a contributed relation or property is about: an
// asset item of the same contribution (Item, counted from 0) or a stored
// asset by an exact field (Type, Field, Value).
type AssetRef struct {
	Item  *int   `json:"item,omitempty"`
	Type  string `json:"type,omitempty"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
}

// ContributedItem is one asset, relation or property an assistant
// contributes, with where it came from and its confidence (0..100; 0 means
// the default).
type ContributedItem struct {
	Kind string `json:"kind"`
	// An asset: its OAM type and fields.
	AssetType string         `json:"asset_type,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	// A relation: From --Label--> To, of RelationType (default
	// SimpleRelation), with the relation's other fields in Fields.
	From         *AssetRef `json:"from,omitempty"`
	Label        string    `json:"label,omitempty"`
	RelationType string    `json:"relation_type,omitempty"`
	To           *AssetRef `json:"to,omitempty"`
	// A property of Target: its OAM type (default SimpleProperty) and its
	// fields in Fields.
	Target       *AssetRef `json:"target,omitempty"`
	PropertyType string    `json:"property_type,omitempty"`
	Evidence     string    `json:"evidence"`
	Confidence   int       `json:"confidence,omitempty"`
}

// Describe names the item for an approval prompt and a listing.
func (it ContributedItem) Describe() string {
	ref := func(r *AssetRef) string {
		switch {
		case r == nil:
			return "?"
		case r.Item != nil:
			return fmt.Sprintf("item %d", *r.Item)
		}
		return fmt.Sprintf("%s %s=%q", r.Type, r.Field, r.Value)
	}
	switch it.Kind {
	case ContributedAsset:
		return fmt.Sprintf("the %s %v", it.AssetType, it.Fields)
	case ContributedRelation:
		return fmt.Sprintf("%s --%s--> %s", ref(it.From), it.Label, ref(it.To))
	case ContributedProperty:
		return fmt.Sprintf("a %s %v on %s", it.PropertyType, it.Fields, ref(it.Target))
	}
	return it.Kind
}

// ContributionTag is a property a contribution wrote: a source tag or a
// contributed property, on an entity or an edge. Existed reports that the
// same property was already there, so undoing the contribution leaves it.
type ContributionTag struct {
	ID      string `json:"id"`
	OnEdge  bool   `json:"on_edge,omitempty"`
	Owner   string `json:"owner"`
	Existed bool   `json:"existed,omitempty"`
}

// ContributionWrite is what writing a contribution changed: the entities and
// edges its items name, and the properties it added to them.
type ContributionWrite struct {
	EntityIDs []string          `json:"entity_ids,omitempty"`
	EdgeIDs   []string          `json:"edge_ids,omitempty"`
	Tags      []ContributionTag `json:"tags,omitempty"`
}

// Contribution journals what an assistant contributed: its items, the
// source they were recorded under, what was written, who approved it and
// the enumerations it was handed to.
type Contribution struct {
	ID       string            `json:"id"`
	Client   string            `json:"client"`
	Source   string            `json:"source"`
	Items    []ContributedItem `json:"items"`
	Write    ContributionWrite `json:"write"`
	Runs     []string          `json:"runs,omitempty"`
	Status   string            `json:"status"`
	Reviewer string            `json:"reviewer"`
	At       time.Time         `json:"at"`
}

// ContributionWriter writes a contribution's items into the Asset Database
// and undoes it.
type ContributionWriter interface {
	WriteContribution(ctx context.Context, source string, items []ContributedItem) (ContributionWrite, error)
	// UndoContribution removes the properties the contribution added and
	// each entity and edge it wrote that no other source recorded.
	UndoContribution(ctx context.Context, source string, w ContributionWrite) error
}

// CheckContribution validates a contribution's items before it is written:
// 1..MaxContributedItems items, each of a known kind with its evidence, and
// a reference to an item only to an earlier asset item.
func CheckContribution(items []ContributedItem) error {
	if len(items) == 0 || len(items) > MaxContributedItems {
		return fmt.Errorf("a contribution holds 1..%d items", MaxContributedItems)
	}

	refOK := func(r *AssetRef, at int) error {
		switch {
		case r == nil:
			return errors.New("names no asset")
		case r.Item != nil:
			if *r.Item < 0 || *r.Item >= at || items[*r.Item].Kind != ContributedAsset {
				return fmt.Errorf("item %d is not an earlier asset item", *r.Item)
			}
		case r.Type == "" || r.Field == "" || r.Value == "":
			return errors.New("a stored asset is named by its type, a field and the field's value")
		}
		return nil
	}
	for i, it := range items {
		if strings.TrimSpace(it.Evidence) == "" {
			return fmt.Errorf("item %d: say where it came from (evidence)", i)
		}
		if it.Confidence < 0 || it.Confidence > 100 {
			return fmt.Errorf("item %d: confidence is 0..100", i)
		}
		var err error
		switch it.Kind {
		case ContributedAsset:
			if it.AssetType == "" || len(it.Fields) == 0 {
				err = errors.New("an asset has a type and fields")
			}
		case ContributedRelation:
			if it.Label == "" {
				err = errors.New("a relation has a label")
			} else if err = refOK(it.From, i); err == nil {
				err = refOK(it.To, i)
			}
		case ContributedProperty:
			if len(it.Fields) == 0 {
				err = errors.New("a property has fields")
			} else {
				err = refOK(it.Target, i)
			}
		default:
			err = fmt.Errorf("unknown kind %q", it.Kind)
		}
		if err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}

// ApplyContribution writes the items under the client's source and journals
// the contribution as applied by reviewer, who approved it. When the journal
// cannot be written, what was written is undone again: nothing is stored
// that cannot be undone.
func ApplyContribution(ctx context.Context, w ContributionWriter, j *Journal, client, reviewer string,
	items []ContributedItem) (Contribution, error) {
	c := Contribution{Client: client, Source: ContributionSource(client), Items: items, Status: ProposalApplied,
		Reviewer: reviewer, At: time.Now().UTC()}
	if strings.TrimSpace(reviewer) == "" {
		return c, errors.New("reviewer required")
	}
	if err := CheckContribution(items); err != nil {
		return c, err
	}

	write, err := w.WriteContribution(ctx, c.Source, items)
	c.Write = write
	if err != nil {
		_ = w.UndoContribution(ctx, c.Source, write)
		return c, err
	}

	sum := sha256.Sum256([]byte(c.Source + "\x00" + c.At.Format(time.RFC3339Nano)))
	c.ID = ContributionPrefix + hex.EncodeToString(sum[:8])
	if err := j.append("contribution", c); err != nil {
		_ = w.UndoContribution(ctx, c.Source, write)
		return c, fmt.Errorf("journal the contribution: %w", err)
	}
	return c, nil
}

// RecordContributionRuns journals the enumerations a contribution was handed
// to.
func (j *Journal) RecordContributionRuns(c Contribution, runs []string) error {
	if len(runs) == 0 {
		return nil
	}
	c.Runs = runs
	return j.append("contribution", c)
}

// Contributions returns the latest record of each contribution, oldest
// first.
func (j *Journal) Contributions() ([]Contribution, error) {
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	byID := map[string]Contribution{}
	var order []string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "contribution" {
			continue
		}
		var c Contribution
		if json.Unmarshal(head.Data, &c) != nil || c.ID == "" {
			continue
		}
		if _, ok := byID[c.ID]; !ok {
			order = append(order, c.ID)
		}
		byID[c.ID] = c
	}

	out := make([]Contribution, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

// RetractContribution undoes an applied contribution (UndoContribution) and
// journals the retraction.
func RetractContribution(ctx context.Context, w ContributionWriter, j *Journal, id, reviewer string) error {
	if strings.TrimSpace(reviewer) == "" {
		return errors.New("reviewer required")
	}

	all, err := j.Contributions()
	if err != nil {
		return err
	}
	for _, c := range all {
		if c.ID != id {
			continue
		}
		if c.Status != ProposalApplied {
			return fmt.Errorf("contribution %s is already %s", id, c.Status)
		}
		if err := w.UndoContribution(ctx, c.Source, c.Write); err != nil {
			return err
		}
		c.Status, c.Reviewer, c.At = ProposalRetracted, reviewer, time.Now().UTC()
		return j.append("contribution", c)
	}
	return fmt.Errorf("no contribution %s", id)
}

// FormatContributions describes contributions for review.
func FormatContributions(all []Contribution) string {
	var b strings.Builder
	for i, c := range all {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s  %s\n", c.ID, strings.ToUpper(c.Status))
		fmt.Fprintf(&b, "  contributed by %s as %s, %s by %s at %s\n", c.Client, c.Source, c.Status, c.Reviewer,
			c.At.Format(time.RFC3339))
		for n, it := range c.Items {
			fmt.Fprintf(&b, "  %d. %s (from %s)\n", n, it.Describe(), it.Evidence)
		}
		if len(c.Runs) > 0 {
			fmt.Fprintf(&b, "  handed to enumeration(s) %s\n", strings.Join(c.Runs, ", "))
		}
	}
	return b.String()
}
