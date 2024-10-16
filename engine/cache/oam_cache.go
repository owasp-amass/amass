// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"sync"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type relations struct {
	all   []*types.Relation
	froms map[string][]*types.Relation
	tos   map[string][]*types.Relation
}

type OAMCache struct {
	sync.Mutex
	cache     Cache
	assets    map[string]map[string]*types.Asset
	relations map[string]*relations
}

func NewOAMCache(c Cache) Cache {
	return &OAMCache{
		cache:     c,
		assets:    make(map[string]map[string]*types.Asset),
		relations: make(map[string]*relations),
	}
}

func (c *OAMCache) Close() {
	c.Lock()
	defer c.Unlock()

	if c.cache != nil {
		c.cache.Close()
	}

	for k := range c.assets {
		clear(c.assets[k])
	}
	clear(c.assets)
	clear(c.relations)
}

func (c *OAMCache) GetAsset(a oam.Asset) (*types.Asset, bool) {
	key := a.Key()
	if key == "" {
		return nil, false
	}

	c.Lock()
	t := string(a.AssetType())
	if m, found := c.assets[t]; found {
		if v, found := m[key]; found {
			c.Unlock()
			return v, true
		}
	}
	c.Unlock()

	if c.cache != nil {
		if v, hit := c.cache.GetAsset(a); v != nil && hit {
			c.SetAsset(v)
			return v, false
		}
	}
	return nil, false
}

func (c *OAMCache) GetAssetsByType(t oam.AssetType) ([]*types.Asset, bool) {
	c.Lock()
	defer c.Unlock()

	var results []*types.Asset
	if set, found := c.assets[string(t)]; found {
		for _, v := range set {
			results = append(results, v)
		}
	}

	if len(results) == 0 {
		return nil, false
	}
	return results, true
}

func (c *OAMCache) SetAsset(a *types.Asset) {
	key := a.Asset.Key()
	if key == "" {
		return
	}

	c.Lock()
	defer c.Unlock()

	t := string(a.Asset.AssetType())
	if _, found := c.assets[t]; !found {
		c.assets[t] = make(map[string]*types.Asset)
	}
	c.assets[t][key] = a
}

func (c *OAMCache) GetRelations(r *types.Relation) ([]*types.Relation, bool) {
	c.Lock()
	if c.relations[r.Type] == nil || (r.FromAsset == nil && r.ToAsset == nil) {
		c.Unlock()
		return nil, false
	}

	var relations []*types.Relation
	if r.FromAsset != nil && r.ToAsset == nil && len(c.relations[r.Type].froms) > 0 {
		if rels, found := c.relations[r.Type].froms[r.FromAsset.ID]; found && len(rels) > 0 {
			relations = append(relations, rels...)
		}
	} else if r.FromAsset == nil && r.ToAsset != nil && len(c.relations[r.Type].tos) > 0 {
		if rels, found := c.relations[r.Type].tos[r.ToAsset.ID]; found && len(rels) > 0 {
			relations = append(relations, rels...)
		}
	} else {
		for _, rel := range c.relations[r.Type].all {
			if r.FromAsset == rel.FromAsset && r.ToAsset == rel.ToAsset {
				relations = append(relations, rel)
			}
		}
	}
	c.Unlock()

	if len(relations) > 0 {
		return relations, true
	}

	if c.cache != nil {
		if rels, hit := c.cache.GetRelations(r); hit && len(rels) > 0 {
			for _, relation := range rels {
				c.SetRelation(relation)
			}
			return rels, false
		}
	}
	return nil, false
}

func (c *OAMCache) GetRelationsByType(rtype string) ([]*types.Relation, bool) {
	c.Lock()
	defer c.Unlock()

	if r := c.relations[rtype]; r != nil && len(r.all) > 0 {
		return r.all, true
	}
	return nil, false
}

func (c *OAMCache) GetIncomingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, bool) {
	var results []*types.Relation
	if asset == nil {
		return results, false
	}

	c.Lock()
	defer c.Unlock()

	if len(relationTypes) == 0 {
		for k := range c.relations {
			if r, found := c.relations[k]; found && r != nil {
				if rels, found := r.tos[asset.ID]; found && len(rels) > 0 {
					results = append(results, rels...)
				}
			}
		}
	} else {
		for _, rel := range relationTypes {
			if r, found := c.relations[rel]; found && r != nil {
				if rels, found := r.tos[asset.ID]; found && len(rels) > 0 {
					results = append(results, rels...)
				}
			}
		}
	}

	var hit bool
	if len(results) > 0 {
		hit = true
	}
	return results, hit
}

func (c *OAMCache) GetOutgoingRelations(asset *types.Asset, relationTypes ...string) ([]*types.Relation, bool) {
	var results []*types.Relation
	if asset == nil {
		return results, false
	}

	c.Lock()
	defer c.Unlock()

	if len(relationTypes) == 0 {
		for k := range c.relations {
			if r, found := c.relations[k]; found && r != nil {
				if rels, found := r.froms[asset.ID]; found && len(rels) > 0 {
					results = append(results, rels...)
				}
			}
		}
	} else {
		for _, rel := range relationTypes {
			if r, found := c.relations[rel]; found && r != nil {
				if rels, found := r.froms[asset.ID]; found && len(rels) > 0 {
					results = append(results, rels...)
				}
			}
		}
	}

	var hit bool
	if len(results) > 0 {
		hit = true
	}
	return results, hit
}

func (c *OAMCache) SetRelation(r *types.Relation) {
	c.Lock()
	defer c.Unlock()

	if _, found := c.relations[r.Type]; !found {
		c.relations[r.Type] = &relations{
			froms: make(map[string][]*types.Relation),
			tos:   make(map[string][]*types.Relation),
		}
	}

	tokey := r.ToAsset.ID
	fromkey := r.FromAsset.ID
	// check for duplicate entries
	if _, found := c.relations[r.Type].froms[fromkey]; found {
		for _, rel := range c.relations[r.Type].froms[fromkey] {
			if rel.ToAsset.ID == tokey {
				return
			}
		}
	}

	c.relations[r.Type].all = append(c.relations[r.Type].all, r)
	c.relations[r.Type].tos[tokey] = append(c.relations[r.Type].tos[tokey], r)
	c.relations[r.Type].froms[fromkey] = append(c.relations[r.Type].froms[fromkey], r)
}
