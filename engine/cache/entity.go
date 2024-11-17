// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// CreateEntity implements the Repository interface.
func (c *Cache) CreateEntity(asset oam.Asset) (*types.Entity, error) {
	c.Lock()
	defer c.Unlock()

	entity, err := c.cache.CreateEntity(asset)
	if err != nil {
		return nil, err
	}

	if tag, found := c.checkCacheEntityTag(entity, "cache_create_entity"); !found {
		if last, err := time.Parse("2006-01-02 15:04:05", tag.Value()); err == nil && time.Now().Add(-1*c.freq).After(last) {
			_ = c.cache.DeleteEntityTag(tag.ID)
			_ = c.createCacheEntityTag(entity, "cache_create_entity")

			c.appendToDBQueue(func() {
				_, _ = c.db.CreateEntity(asset)
			})
		}
	}

	return entity, nil
}

// UpdateEntityLastSeen implements the Repository interface.
func (c *Cache) UpdateEntityLastSeen(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.UpdateEntityLastSeen(id)
	if err != nil {
		return err
	}

	entity, err := c.cache.FindEntityById(id)
	if err != nil {
		return nil
	}

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_ = c.db.UpdateEntityLastSeen(e[0].ID)
		}
	})

	return nil
}

// FindEntityById implements the Repository interface.
func (c *Cache) FindEntityById(id string) (*types.Entity, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEntityById(id)
}

// FindEntityByContent implements the Repository interface.
func (c *Cache) FindEntityByContent(asset oam.Asset, since time.Time) ([]*types.Entity, error) {
	c.Lock()
	entities, err := c.cache.FindEntityByContent(asset, since)
	if err == nil && len(entities) == 1 {
		if !since.IsZero() && !since.Before(c.start) {
			c.Unlock()
			return entities, err
		}
		if _, found := c.checkCacheEntityTag(entities[0], "cache_find_entity_by_content"); found {
			c.Unlock()
			return entities, err
		}
	}
	c.Unlock()

	var dberr error
	var dbentities []*types.Entity
	done := make(chan struct{}, 1)
	c.appendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		dbentities, dberr = c.db.FindEntityByContent(asset, since)
	})
	<-done
	close(done)

	if dberr != nil {
		return entities, err
	}

	c.Lock()
	defer c.Unlock()

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(entity.Asset); err == nil {
			results = append(results, e)
			if tags, err := c.cache.GetEntityTags(entity, c.start, "cache_find_entity_by_content"); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					_ = c.cache.DeleteEntityTag(tag.ID)
				}
			}
			_ = c.createCacheEntityTag(entity, "cache_find_entity_by_content")
		}
	}
	return results, nil
}

// FindEntitiesByType implements the Repository interface.
func (c *Cache) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	c.Lock()
	entities, err := c.cache.FindEntitiesByType(atype, since)
	if err == nil && len(entities) > 0 {
		if !since.IsZero() && !since.Before(c.start) {
			c.Unlock()
			return entities, err
		}
		if _, found := c.checkCacheEntityTag(entities[0], "cache_find_entities_by_type"); found {
			c.Unlock()
			return entities, err
		}
	}
	c.Unlock()

	var dberr error
	var dbentities []*types.Entity
	done := make(chan struct{}, 1)
	c.appendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		dbentities, dberr = c.db.FindEntitiesByType(atype, since)
	})
	<-done
	close(done)

	if dberr != nil {
		return entities, err
	}

	c.Lock()
	defer c.Unlock()

	var results []*types.Entity
	for _, entity := range dbentities {
		if e, err := c.cache.CreateEntity(entity.Asset); err == nil {
			results = append(results, e)
			if tags, err := c.cache.GetEntityTags(entity, c.start, "cache_find_entities_by_type"); err == nil && len(tags) > 0 {
				for _, tag := range tags {
					_ = c.cache.DeleteEntityTag(tag.ID)
				}
			}
			_ = c.createCacheEntityTag(entity, "cache_find_entities_by_type")
		}
	}
	return results, nil
}

// DeleteEntity implements the Repository interface.
func (c *Cache) DeleteEntity(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.DeleteEntity(id)
	if err != nil {
		return err
	}

	entity, err := c.cache.FindEntityById(id)
	if err != nil {
		return nil
	}

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			_ = c.db.DeleteEntity(e[0].ID)
		}
	})

	return nil
}
