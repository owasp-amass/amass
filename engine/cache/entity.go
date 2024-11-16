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

	c.appendToDBQueue(func() {
		_, _ = c.db.CreateEntity(asset)
	})

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
	defer c.Unlock()

	return c.cache.FindEntityByContent(asset, since)
}

// FindEntitiesByType implements the Repository interface.
func (c *Cache) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEntitiesByType(atype, since)
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
