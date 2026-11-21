// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// StoredBucket is an object-storage bucket the bucket probe recorded for a
// host the footprint reaches: one entry per bucket, however many host names
// address it.
type StoredBucket struct {
	Bucket   graph.Asset `json:"bucket"`
	Name     string      `json:"name"`
	Provider string      `json:"provider,omitempty"`
	// Exists is false when the provider reported the bucket missing: a name
	// that still reaches it is a takeover target (see the dangling lens).
	Exists bool `json:"exists"`
	// Public is true when the bucket's listing was world-readable.
	Public bool `json:"public"`
	// Hosts are the bucket host names that address it; Via are the
	// footprint names that alias to one of them.
	Hosts []string `json:"hosts"`
	Via   []string `json:"via,omitempty"`
}

// String describes the bucket and its state.
func (b StoredBucket) String() string {
	state := "private"
	switch {
	case !b.Exists:
		state = "missing at the provider"
	case b.Public:
		state = "world-readable"
	}

	s := b.Name
	if b.Provider != "" {
		s = b.Provider + " bucket " + s
	}
	return s + " (" + state + ")"
}

// bucketHost returns the object-storage bucket host a footprint name is, or
// aliases to through its CNAME chain, and the name that addresses it.
func bucketHost(w *lensWalker, a graph.Asset) (graph.Asset, bool, error) {
	if _, _, ok := semantics.MatchBucketHost(graph.FQDNName(a)); ok {
		return a, true, nil
	}

	res, err := resolveName(w, a)
	if err != nil || !res.Aliased() {
		return graph.Asset{}, false, err
	}

	target := res.Target(a)
	if _, _, ok := semantics.MatchBucketHost(graph.FQDNName(target)); !ok {
		return graph.Asset{}, false, nil
	}
	return target, true, nil
}

// storedBucket returns the StorageBucket the probe recorded on a bucket
// host's "bucket" relation, if any.
func storedBucket(w *lensWalker, host graph.Asset) (graph.Asset, bool, error) {
	steps, err := w.steps(host)
	if err != nil {
		return graph.Asset{}, false, err
	}

	for _, s := range steps {
		if s.forward && s.edge.Label == "bucket" && s.other.Type == "StorageBucket" {
			return s.other, true, nil
		}
	}
	return graph.Asset{}, false, nil
}

// bucketExists and bucketPublic read a stored bucket's state.
func bucketExists(b graph.Asset) bool { return contentBool(b, "exists") }
func bucketPublic(b graph.Asset) bool { return contentBool(b, "public") }

// bucketInventory collects the stored buckets the given footprint names are,
// or alias to, merged per bucket and sorted by name.
type bucketInventory struct {
	byID  map[string]*StoredBucket
	order []string
}

func (inv *bucketInventory) add(bucket, host, name graph.Asset) {
	if inv.byID == nil {
		inv.byID = map[string]*StoredBucket{}
	}

	b, ok := inv.byID[bucket.ID]
	if !ok {
		b = &StoredBucket{
			Bucket:   bucket,
			Name:     graph.ContentString(bucket, "bucket_name"),
			Provider: graph.ContentString(bucket, "provider"),
			Exists:   bucketExists(bucket),
			Public:   bucketPublic(bucket),
		}
		if b.Name == "" {
			b.Name = bucket.Key
		}
		inv.byID[bucket.ID] = b
		inv.order = append(inv.order, bucket.ID)
	}

	graph.AddUnique(&b.Hosts, graph.FQDNName(host))
	if name.ID != host.ID {
		graph.AddUnique(&b.Via, graph.FQDNName(name))
	}
}

func (inv *bucketInventory) list() []StoredBucket {
	out := make([]StoredBucket, 0, len(inv.order))
	for _, id := range inv.order {
		b := *inv.byID[id]
		sort.Strings(b.Hosts)
		sort.Strings(b.Via)
		out = append(out, b)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// writeBuckets renders a buckets section.
func writeBuckets(b *strings.Builder, buckets []StoredBucket) {
	if len(buckets) == 0 {
		return
	}

	fmt.Fprintf(b, "\nObject-storage buckets (%d):\n", len(buckets))
	for _, sb := range buckets {
		fmt.Fprintf(b, "  %s at %s", sb, strings.Join(sb.Hosts, ", "))
		if len(sb.Via) > 0 {
			fmt.Fprintf(b, " via %s", strings.Join(sb.Via, ", "))
		}
		b.WriteString("\n")
	}
}
