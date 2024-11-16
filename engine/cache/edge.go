// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"time"

	"github.com/owasp-amass/asset-db/types"
)

// Link implements the Repository interface.
func (c *Cache) Link(edge *types.Edge) (*types.Edge, error) {
	c.Lock()
	defer c.Unlock()

	e, err := c.cache.Link(edge)
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

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.DeleteEdge(id)
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
