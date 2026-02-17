// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"crypto/sha1"
	"fmt"
	"sort"
)

type hashRingNode struct {
	hash uint32
	id   string
}

// hashRing is a minimal consistent-hash ring for mapping shard keys to instance IDs.
type hashRing struct {
	replicas int
	nodes    []hashRingNode // sorted by hash
}

func newHashRing(replicas int) *hashRing {
	if replicas <= 0 {
		replicas = 50
	}
	return &hashRing{replicas: replicas}
}

func (r *hashRing) Add(id string) {
	for i := 0; i < r.replicas; i++ {
		key := fmt.Sprintf("%s#%d", id, i)
		h := hashKey(key)
		r.nodes = append(r.nodes, hashRingNode{hash: h, id: id})
	}

	sort.Slice(r.nodes, func(i, j int) bool {
		return r.nodes[i].hash < r.nodes[j].hash
	})
}

func (r *hashRing) Remove(id string) {
	out := r.nodes[:0]

	for _, n := range r.nodes {
		if n.id != id {
			out = append(out, n)
		}
	}

	r.nodes = out
}

func (r *hashRing) Lookup(key string) (string, bool) {
	if len(r.nodes) == 0 {
		return "", false
	}

	h := hashKey(key)
	idx := sort.Search(len(r.nodes), func(i int) bool {
		return r.nodes[i].hash >= h
	})

	if idx == len(r.nodes) {
		idx = 0
	}

	return r.nodes[idx].id, true
}

func hashKey(s string) uint32 {
	sum := sha1.Sum([]byte(s))
	// take first 4 bytes as uint32
	return uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
}
