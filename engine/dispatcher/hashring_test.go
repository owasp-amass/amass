// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ------------------------------
// Core behavior tests
// ------------------------------

func TestHashRingLookupEmpty(t *testing.T) {
	r := newHashRing(50)
	id, ok := r.Lookup("anything")
	assert.False(t, ok)
	assert.Equal(t, "", id)
}

func TestHashRingAddCreatesReplicasAndSorts(t *testing.T) {
	r := newHashRing(10)
	r.Add("A")
	r.Add("B")

	require.Len(t, r.nodes, 20, "replicas * instances nodes expected")

	// Ensure sorted by hash non-decreasing
	for i := 1; i < len(r.nodes); i++ {
		assert.LessOrEqual(t, r.nodes[i-1].hash, r.nodes[i].hash)
	}

	// Ensure each ID appears exactly replicas times
	var a, b int
	for _, n := range r.nodes {
		switch n.id {
		case "A":
			a++
		case "B":
			b++
		default:
			t.Fatalf("unexpected node id: %s", n.id)
		}
	}
	assert.Equal(t, 10, a)
	assert.Equal(t, 10, b)
}

func TestHashRingRemoveRemovesAllReplicas(t *testing.T) {
	r := newHashRing(25)
	r.Add("A")
	r.Add("B")
	r.Add("C")

	require.Len(t, r.nodes, 75)

	r.Remove("B")

	// B should be gone
	for _, n := range r.nodes {
		assert.NotEqual(t, "B", n.id)
	}
	// Only A and C remain
	require.Len(t, r.nodes, 50)

	// Removing non-existent should be a no-op
	before := len(r.nodes)
	r.Remove("does-not-exist")
	assert.Equal(t, before, len(r.nodes))
}

func TestHashRingLookupIsDeterministic(t *testing.T) {
	r := newHashRing(50)
	r.Add("A")
	r.Add("B")
	r.Add("C")

	keys := []string{
		"session-1",
		"session-1/0",
		"session-999/17",
		"fallback-deadbeef",
		"some/arbitrary/key",
	}

	for _, k := range keys {
		first, ok := r.Lookup(k)
		require.True(t, ok)
		for range 100 {
			next, ok := r.Lookup(k)
			require.True(t, ok)
			assert.Equal(t, first, next, "lookup should be deterministic for key %q", k)
		}
	}
}

func TestHashRingLookupWrapAround(t *testing.T) {
	// Construct a ring where we can reliably pick a key that hashes beyond max node hash:
	// Because hashKey is uniform-ish, we can brute force a key with hash > max.
	r := newHashRing(5)
	r.Add("A")
	r.Add("B")
	r.Add("C")

	require.NotEmpty(t, r.nodes)
	maxHash := r.nodes[len(r.nodes)-1].hash

	var key string
	found := false
	for i := range 200000 {
		k := fmt.Sprintf("probe-%d", i)
		if hashKey(k) > maxHash {
			key = k
			found = true
			break
		}
	}
	require.True(t, found, "expected to find a key hashing above max node hash")

	id, ok := r.Lookup(key)
	require.True(t, ok)
	// Wrap-around means we pick nodes[0].id
	assert.Equal(t, r.nodes[0].id, id)
}

// ------------------------------
// Dispatcher/pool-use-case tests
// ------------------------------

// In the dispatcher pipeline pool, the ring maps shardKey -> instanceID.
// Desired properties:
// 1) Stability: same shardKey maps to same instance unless membership changes.
// 2) Minimal remapping on scale-up/down (consistent hashing property).
// 3) Reasonable load distribution across instances (not perfect, but should not be pathological).
func TestHashRingStableAssignmentsUntilMembershipChange(t *testing.T) {
	r := newHashRing(50)
	for i := 1; i <= 8; i++ {
		r.Add(fmt.Sprintf("inst-%d", i))
	}

	keys := makeShardKeys(5000, 42)
	before := mapAssignments(r, keys)

	// Re-run without changes: should be identical
	after := mapAssignments(r, keys)
	assert.Equal(t, before, after)
}

func TestHashRingMinimalRemapOnScaleUp(t *testing.T) {
	r := newHashRing(50)
	for i := 1; i <= 8; i++ {
		r.Add(fmt.Sprintf("inst-%d", i))
	}

	keys := makeShardKeys(20000, 99)
	before := mapAssignments(r, keys)

	// Scale up: add one instance
	r.Add("inst-9")
	after := mapAssignments(r, keys)

	remapped := fractionRemapped(before, after)

	// Consistent hashing expectation: ~1/(n+1) keys move to new node (~11.1% when going 8->9).
	// Allow generous tolerance because of randomness/replicas/hash collisions.
	expected := 1.0 / 9.0
	assert.InDelta(t, expected, remapped, 0.06, "remapped fraction should be near 1/(n+1) on scale-up")
}

func TestHashRingMinimalRemapOnScaleDown(t *testing.T) {
	r := newHashRing(50)
	for i := 1; i <= 9; i++ {
		r.Add(fmt.Sprintf("inst-%d", i))
	}

	keys := makeShardKeys(20000, 123)
	before := mapAssignments(r, keys)

	// Scale down: remove one instance
	r.Remove("inst-9")
	after := mapAssignments(r, keys)

	remapped := fractionRemapped(before, after)

	// Removing a node should remap primarily those keys that mapped to it: ~1/n (here 1/9 ~11.1%).
	expected := 1.0 / 9.0
	assert.InDelta(t, expected, remapped, 0.06, "remapped fraction should be near 1/n on scale-down")
}

func TestHashRingDistributionNotPathological(t *testing.T) {
	// This is not a strict uniformity test; it is a "no glaring hotspot" test
	// for typical dispatcher shard keys (session IDs + bucket suffixes).
	r := newHashRing(50)
	nInst := 16
	for i := 1; i <= nInst; i++ {
		r.Add(fmt.Sprintf("inst-%02d", i))
	}

	keys := makeShardKeys(50000, time.Now().UnixNano())
	counts := countAssignments(r, keys)

	require.Len(t, counts, nInst, "all instances should receive some keys with sufficient sample size")

	// Compute mean and standard deviation of assigned counts
	var sum float64
	vals := make([]float64, 0, nInst)
	for i := 1; i <= nInst; i++ {
		v := float64(counts[fmt.Sprintf("inst-%02d", i)])
		vals = append(vals, v)
		sum += v
	}
	mean := sum / float64(nInst)

	var ss float64
	for _, v := range vals {
		d := v - mean
		ss += d * d
	}
	std := math.Sqrt(ss / float64(nInst))

	// Coefficient of variation (std/mean) should be "reasonably small".
	// With 50 replicas and 50k keys, CV should typically be under ~0.10–0.15.
	// We allow 0.20 to avoid flakiness across environments.
	cv := std / mean
	assert.Less(t, cv, 0.20, "distribution CV too high; possible hotspotting or too few replicas")

	// Also ensure no single instance has > ~2x the mean (very lax).
	var max float64
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	assert.Less(t, max, 2.0*mean, "one instance has >2x mean assignments; unexpected hotspot")
}

func TestHashRingRemoveInstanceNeverReturned(t *testing.T) {
	r := newHashRing(25)
	for i := 1; i <= 6; i++ {
		r.Add(fmt.Sprintf("inst-%d", i))
	}

	keys := makeShardKeys(10000, 7)
	before := mapAssignments(r, keys)

	r.Remove("inst-3")

	for k, id := range before {
		after, ok := r.Lookup(k)
		require.True(t, ok)
		assert.NotEqual(t, "inst-3", after, "removed instance must never be returned")

		// Keys that were not on inst-3 should usually remain stable, but not guaranteed.
		// We do not assert stability here beyond "not removed".
		_ = id
	}
}

func TestHashRingReplicaCountMattersForDistribution(t *testing.T) {
	// Demonstrate why your default replicas (50) is a good fit:
	// with very low replicas, distribution worsens noticeably.
	keys := makeShardKeys(40000, 2026)

	buildCV := func(replicas int) float64 {
		r := newHashRing(replicas)
		nInst := 12
		for i := 1; i <= nInst; i++ {
			r.Add(fmt.Sprintf("inst-%02d", i))
		}
		counts := countAssignments(r, keys)

		var sum float64
		vals := make([]float64, 0, nInst)
		for i := 1; i <= nInst; i++ {
			v := float64(counts[fmt.Sprintf("inst-%02d", i)])
			vals = append(vals, v)
			sum += v
		}
		mean := sum / float64(nInst)

		var ss float64
		for _, v := range vals {
			d := v - mean
			ss += d * d
		}
		std := math.Sqrt(ss / float64(nInst))
		return std / mean
	}

	cvLow := buildCV(1)
	cvHigh := buildCV(50)

	// With 1 replica, CV should be worse than with 50 replicas.
	// We don't enforce absolute values; just verify the relative improvement.
	assert.Greater(t, cvLow, cvHigh, "expected higher replicas to improve distribution")
}

// ------------------------------
// hashKey test (sanity)
// ------------------------------

func TestHashKeySameInputSameOutput(t *testing.T) {
	a := hashKey("hello")
	b := hashKey("hello")
	c := hashKey("hello#0")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
}

func TestHashKeyReasonableSpread(t *testing.T) {
	// Very light sanity test: hashes should not all collapse to same value.
	seen := map[uint32]struct{}{}
	for i := range 5000 {
		seen[hashKey(fmt.Sprintf("k-%d", i))] = struct{}{}
	}
	// collisions can happen, but should be very few at this scale
	assert.Greater(t, len(seen), 4900)
}

func TestHashRingOnePipelinePerShardKeyAndFanoutSpreadsLoad(t *testing.T) {
	// This test is tailored to the pipeline pool contract:
	// - "one pipeline per (assetType, shardKey) at a time": shardKey deterministically maps to exactly one instance.
	// - When fanout>1, shard keys look like "sessionID/bucket" and should spread across multiple instances
	//   (not necessarily perfectly uniform, but not all to one instance).

	const (
		replicas     = 50
		numInstances = 16

		numSessions = 200
		fanout      = 32 // buckets per session
	)

	r := newHashRing(replicas)
	for i := 1; i <= numInstances; i++ {
		r.Add(fmt.Sprintf("inst-%02d", i))
	}

	// 1) Determinism: each shardKey always maps to exactly one instance (stable mapping).
	// We'll verify by mapping twice and comparing results.
	first := make(map[string]string, numSessions*fanout)
	second := make(map[string]string, numSessions*fanout)

	for s := range numSessions {
		sid := fmt.Sprintf("session-%d", s)

		// Include base (fanout=1) style key as well.
		baseKey := sid
		id1, ok := r.Lookup(baseKey)
		require.True(t, ok)
		first[baseKey] = id1

		id2, ok := r.Lookup(baseKey)
		require.True(t, ok)
		second[baseKey] = id2

		for b := range fanout {
			shardKey := fmt.Sprintf("%s/%d", sid, b)

			id1, ok := r.Lookup(shardKey)
			require.True(t, ok)
			first[shardKey] = id1

			// Repeat lookup to verify deterministic mapping for that shardKey.
			id2, ok := r.Lookup(shardKey)
			require.True(t, ok)
			second[shardKey] = id2
		}
	}

	assert.Equal(t, first, second, "each shardKey must map deterministically to one instance")

	// 2) Fanout spread: for each session with buckets, the bucketed shardKeys should normally
	// map to multiple instances (i.e., the ring provides parallelism opportunity).
	//
	// We do NOT require all sessions to spread widely (randomness), but in aggregate:
	// - most sessions should touch >1 instance
	// - overall bucket assignments should span many instances
	//
	// This matches your dispatcher use case: session fanout should distribute load.
	sessionDistinct := make([]int, 0, numSessions)
	globalCounts := make(map[string]int)

	for s := range numSessions {
		sid := fmt.Sprintf("session-%d", s)
		distinct := make(map[string]struct{})

		for b := range fanout {
			shardKey := fmt.Sprintf("%s/%d", sid, b)
			id := first[shardKey]
			distinct[id] = struct{}{}
			globalCounts[id]++
		}
		sessionDistinct = append(sessionDistinct, len(distinct))
	}

	// Count how many sessions had buckets mapped to more than 1 instance.
	var spreadSessions int
	for _, d := range sessionDistinct {
		if d > 1 {
			spreadSessions++
		}
	}

	// With 16 instances and 32 buckets, it would be very surprising if a large fraction
	// of sessions all mapped to a single instance.
	// Use a conservative threshold to avoid flakiness.
	assert.GreaterOrEqual(t, spreadSessions, int(float64(numSessions)*0.90),
		"expected at least 90%% of sessions to have bucket fanout spread across >1 instance")

	// Globally, buckets should hit all instances (or nearly all).
	// Again, conservative: require at least 75% of instances to be used.
	usedInstances := 0
	for i := 1; i <= numInstances; i++ {
		if globalCounts[fmt.Sprintf("inst-%02d", i)] > 0 {
			usedInstances++
		}
	}
	assert.GreaterOrEqual(t, usedInstances, int(float64(numInstances)*0.75),
		"expected fanout buckets to utilize at least 75%% of instances")

	// Optional sanity: no single instance should take an extreme share of buckets.
	// Total buckets = numSessions * fanout.
	totalBuckets := numSessions * fanout
	mean := float64(totalBuckets) / float64(numInstances)

	var max float64
	for _, c := range globalCounts {
		if float64(c) > max {
			max = float64(c)
		}
	}
	assert.Less(t, max, 2.0*mean, "unexpected hotspot: an instance received >2x mean bucket load")
}

// ------------------------------
// Helpers
// ------------------------------

func makeShardKeys(n int, seed int64) []string {
	r := rand.New(rand.NewSource(seed))
	keys := make([]string, 0, n)
	for i := range n {
		// Simulate dispatcher shard keys: session/bucket-like keys plus some raw session keys.
		switch i % 3 {
		case 0:
			keys = append(keys, fmt.Sprintf("session-%d", r.Intn(5000)))
		case 1:
			keys = append(keys, fmt.Sprintf("session-%d/%d", r.Intn(2000), r.Intn(64)))
		default:
			keys = append(keys, fmt.Sprintf("fallback-%08x", r.Uint32()))
		}
	}
	return keys
}

func countAssignments(r *hashRing, keys []string) map[string]int {
	counts := make(map[string]int)
	for _, k := range keys {
		id, ok := r.Lookup(k)
		if !ok {
			continue
		}
		counts[id]++
	}
	return counts
}

func fractionRemapped(before, after map[string]string) float64 {
	if len(before) == 0 {
		return 0
	}
	var changed int
	for k, b := range before {
		if a, ok := after[k]; ok && a != b {
			changed++
		}
	}
	return float64(changed) / float64(len(before))
}

func mapAssignments(r *hashRing, keys []string) map[string]string {
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		id, ok := r.Lookup(k)
		if ok {
			m[k] = id
		}
	}
	return m
}
