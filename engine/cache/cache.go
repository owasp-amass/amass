// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"errors"
	"sync"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlrepo"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type Cache struct {
	sync.Mutex
	cache repository.Repository
	db    repository.Repository
}

func New(database repository.Repository) (repository.Repository, error) {
	if c := assetdb.New(sqlrepo.SQLiteMemory, ""); c != nil {
		return &Cache{
			cache: c,
			db:    database,
		}, nil
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

	return nil
}

// GetDBType implements the Repository interface.
func (c *Cache) GetDBType() string {
	return c.db.GetDBType()
}

// CreateEntity implements the Repository interface.
func (c *Cache) CreateEntity(asset oam.Asset) (*types.Entity, error) {

}

// UpdateEntityLastSeen implements the Repository interface.
func (c *Cache) UpdateEntityLastSeen(id string) error {

}

// DeleteEntity implements the Repository interface.
func (c *Cache) DeleteEntity(id string) error {

}

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(id string) error {

}

// FindEntityById implements the Repository interface.
func (c *Cache) FindEntityById(id string) (*types.Entity, error) {

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

}

// IncomingEdges implements the Repository interface.
func (c *Cache) IncomingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {

}

// OutgoingEdges implements the Repository interface.
func (c *Cache) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {

}

// CreateEntityTag implements the Repository interface.
func (c *Cache) CreateEntityTag(entity *types.Entity, property oam.Property) (*types.EntityTag, error) {

}

// GetEntityTags implements the Repository interface.
func (c *Cache) GetEntityTags(entity *types.Entity, since time.Time, names ...string) ([]*types.EntityTag, error) {

}

// DeleteEntityTag implements the Repository interface.
func (c *Cache) DeleteEntityTag(id string) error {

}

// CreateEdgeTag implements the Repository interface.
func (c *Cache) CreateEdgeTag(edge *types.Edge, property oam.Property) (*types.EdgeTag, error) {

}

// GetEdgeTags implements the Repository interface.
func (c *Cache) GetEdgeTags(edge *types.Edge, since time.Time, names ...string) ([]*types.EdgeTag, error) {

}

// DeleteEdgeTag implements the Repository interface.
func (c *Cache) DeleteEdgeTag(id string) error {

}
