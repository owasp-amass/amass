// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"reflect"
	"time"

	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/property"
)

// CreateEntityTag implements the Repository interface.
func (c *Cache) CreateEntityTag(entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	c.Lock()
	defer c.Unlock()

	tag, err := c.cache.CreateEntityTag(entity, property)
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		_, _ = c.db.CreateEntityTag(entity, property)
	})

	return tag, nil
}

// FindEntityTagById implements the Repository interface.
func (c *Cache) FindEntityTagById(id string) (*types.EntityTag, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEntityTagById(id)
}

// GetEntityTags implements the Repository interface.
func (c *Cache) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.GetEntityTags(entity, since, names...)
}

// DeleteEntityTag implements the Repository interface.
func (c *Cache) DeleteEntityTag(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.DeleteEntityTag(id)
	if err != nil {
		return err
	}

	tag, err := c.cache.FindEntityTagById(id)
	if err != nil {
		return nil
	}

	entity, err := c.cache.FindEntityById(tag.Entity.ID)
	if err != nil {
		return nil
	}

	c.appendToDBQueue(func() {
		if e, err := c.db.FindEntityByContent(entity.Asset, time.Time{}); err == nil && len(e) == 1 {
			if tags, err := c.db.GetEntityTags(e, time.Time{}, tag.Name()); err == nil && len(tags) > 0 {
				for _, t := range tags {
					if t.Value() == tag.Value() {
						_ = c.db.DeleteEntity(t.ID)
						break
					}
				}
			}
		}
	})

	return nil
}

// CreateEdgeTag implements the Repository interface.
func (c *Cache) CreateEdgeTag(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	c.Lock()
	defer c.Unlock()

	tag, err := c.cache.CreateEdgeTag(edge, property)
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		_, _ = c.db.CreateEdgeTag(edge, property)
	})

	return tag, nil
}

// FindEdgeTagById implements the Repository interface.
func (c *Cache) FindEdgeTagById(id string) (*types.EdgeTag, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.FindEdgeTagById(id)
}

// GetEdgeTags implements the Repository interface.
func (c *Cache) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.GetEdgeTags(edge, since, names...)
}

// DeleteEdgeTag implements the Repository interface.
func (c *Cache) DeleteEdgeTag(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.DeleteEdgeTag(id)
	if err != nil {
		return err
	}

	tag, err := c.cache.FindEdgeTagById(id)
	if err != nil {
		return nil
	}

	sub, err := c.cache.FindEntityById(tag.Edge.FromEntity.ID)
	if err != nil {
		return nil
	}

	obj, err := c.cache.FindEntityById(tag.Edge.ToEntity.ID)
	if err != nil {
		return nil
	}

	c.appendToDBQueue(func() {
		s, err := c.db.FindEntityByContent(sub.Asset, time.Time{})
		if err != nil || len(s) != 1 {
			return
		}

		o, err := c.db.FindEntityByContent(obj.Asset, time.Time{})
		if err != nil || len(o) != 1 {
			return
		}

		edges, err := c.db.OutgoingEdges(s, time.Time{}, tag.Edge.Relation.Label())
		if err != nil || len(edges) == 0 {
			return
		}

		var target *types.Edge
		for _, e := range edges {
			if e.ID == o.ID && reflect.DeepEqual(e.Relation, o.Relation) {
				target = e
				break
			}
		}
		if target == nil {
			return
		}

		if tags, err := c.db.GetEdgeTags(target, time.Time{}, tag.Name()); err == nil && len(tags) > 0 {
			for _, t := range tags {
				if tag.Property.Value() == t.Property.Value() {
					_ = c.db.DeleteEdgeTag(t.ID)
					break
				}
			}
		}
	})

	return nil
}

func (c *Cache) createCacheEntityTag(entity *types.Entity, name string) error {
	_, err := c.cache.CreateEntityTag(entity, &property.SimpleProperty{
		PropertyName:  name,
		PropertyValue: time.Now().Format("2006-01-02 15:04:05"),
	})
	return err
}

func (c *Cache) checkCacheEntityTag(entity *types.Entity, name string) (*types.EntityTag, bool) {
	if tags, err := c.cache.GetEntityTags(entity, time.Time{}, name); err == nil && len(tags) == 1 {
		return tags[0], true
	}
	return nil, false
}

func (c *Cache) createCacheEdgeTag(edge *types.Edge, name string) error {
	_, err := c.cache.CreateEdgeTag(edge, &property.SimpleProperty{
		PropertyName:  name,
		PropertyValue: time.Now().Format("2006-01-02 15:04:05"),
	})
	return err
}

func (c *Cache) checkCacheEdgeTag(edge *types.Edge, name string) (*types.EdgeTag, bool) {
	if tags, err := c.cache.GetEdgeTags(edge, time.Time{}, name); err == nil && len(tags) == 1 {
		return tags[0], true
	}
	return nil, false
}
