// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"sync"
	"time"

	"github.com/caffix/queue"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Cache struct {
	sync.Mutex
	done  chan struct{}
	cache repository.Repository
	db    repository.Repository
	queue queue.Queue
}

func New(database repository.Repository) (repository.Repository, error) {
	if db := assetdb.New(sqlrepo.SQLiteMemory, ""); db != nil {
		c := &Cache{
			cache: db.Repo,
			done:  make(chan struct{}, 1),
			db:    database,
			queue: queue.NewQueue(),
		}

		go c.processDBCallbacks()
		return c, nil
	}

	return nil, errors.New("failed to create the cache repository")
}

// Close implements the Repository interface.
func (c *Cache) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.cache != nil {
		if err := c.cache.Close(); err != nil {
			return err
		}
	}

	close(c.done)
	for {
		if c.queue.Empty() {
			break
		}
		time.Sleep(5 * time.Second)
	}
	return nil
}

// GetDBType implements the Repository interface.
func (c *Cache) GetDBType() string {
	return c.db.GetDBType()
}

// CreateEntity implements the Repository interface.
func (c *Cache) CreateEntity(asset oam.Asset) (*types.Entity, error) {
	c.Lock()
	entity, err := c.cache.CreateEntity(asset)
	c.Unlock()
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
	err := c.cache.UpdateEntityLastSeen(id)
	if err != nil {
		c.Unlock()
		return err
	}

	entity, err := c.cache.FindEntityById(id)
	c.Unlock()
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

// DeleteEntity implements the Repository interface.
func (c *Cache) DeleteEntity(id string) error {
	c.Lock()
	err := c.cache.DeleteEntity(id)
	if err != nil {
		c.Unlock()
		return err
	}

	entity, err := c.cache.FindEntityById(id)
	c.Unlock()
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

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(id string) error {
	c.Lock()
	err := c.cache.DeleteEdge(id)
	if err != nil {
		c.Unlock()
		return err
	}

	entity, err := c.cache.FindEntityById(id)
	c.Unlock()
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

}

// FindEntitiesByType implements the Repository interface.
func (c *Cache) FindEntitiesByType(atype oam.AssetType, since time.Time) ([]*types.Entity, error) {

}

// FindEntitiesByScope implements the Repository interface.
func (c *Cache) FindEntitiesByScope(constraints []oam.Asset, since time.Time) ([]*types.Entity, error) {

}

// Link implements the Repository interface.
func (c *Cache) Link(edge *types.Edge) (*types.Edge, error) {
	c.Lock()
	e, err := c.cache.Link(edge)
	c.Unlock()
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		_, _ = c.db.Link(edge)
	})

	return e, nil
}

// IncomingEdges implements the Repository interface.
func (c *Cache) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {

}

// OutgoingEdges implements the Repository interface.
func (c *Cache) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {

}

// CreateEntityTag implements the Repository interface.
func (c *Cache) CreateEntityTag(entity *types.Entity, property oam.Property) (*types.EntityTag, error) {
	c.Lock()
	tag, err := c.cache.CreateEntityTag(entity, property)
	c.Unlock()
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		_, _ = c.db.CreateEntityTag(entity, property)
	})

	return tag, nil
}

// GetEntityTags implements the Repository interface.
func (c *Cache) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {

}

// DeleteEntityTag implements the Repository interface.
func (c *Cache) DeleteEntityTag(id string) error {

}

// CreateEdgeTag implements the Repository interface.
func (c *Cache) CreateEdgeTag(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {
	c.Lock()
	tag, err := c.cache.CreateEdgeTag(edge, property)
	c.Unlock()
	if err != nil {
		return nil, err
	}

	c.appendToDBQueue(func() {
		_, _ = c.db.CreateEdgeTag(edge, property)
	})

	return tag, nil
}

// GetEdgeTags implements the Repository interface.
func (c *Cache) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {

}

// DeleteEdgeTag implements the Repository interface.
func (c *Cache) DeleteEdgeTag(id string) error {

}

func (c *Cache) appendToDBQueue(callback func()) {
	c.queue.Append(callback)
}

func (c *Cache) processDBCallbacks() {
loop:
	for {
		select {
		case <-c.done:
			break loop
		case <-c.queue.Signal():
			element, ok := c.queue.Next()

			for i := 0; i < 10 && ok; i++ {
				if callback, success := element.(func()); success {
					callback()
				}

				element, ok = c.queue.Next()
			}
		}
	}

	c.queue.Process(func(data interface{}) {
		if callback, ok := data.(func()); ok {
			callback()
		}
	})
}
