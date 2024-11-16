// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"reflect"
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
	c.Lock()
	defer c.Unlock()

	return c.cache.IncomingEdges(entity, since, labels...)
}

// OutgoingEdges implements the Repository interface.
func (c *Cache) OutgoingEdges(entity *types.Entity, since time.Time, labels ...string) ([]*types.Edge, error) {
	c.Lock()
	defer c.Unlock()

	return c.cache.OutgoingEdges(entity, since, labels...)
}

// DeleteEdge implements the Repository interface.
func (c *Cache) DeleteEdge(id string) error {
	c.Lock()
	defer c.Unlock()

	err := c.cache.DeleteEdge(id)
	if err != nil {
		return err
	}

	edge, err := c.cache.FindEdgeById(id)
	if err != nil {
		return nil
	}

	sub, err := c.cache.FindEntityById(edge.FromEntity.ID)
	if err != nil {
		return nil
	}

	obj, err := c.cache.FindEntityById(edge.ToEntity.ID)
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

		edges, err := c.db.OutgoingEdges(s, time.Time{}, edge.Relation.Label())
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
		if target != nil {
			_ = c.db.DeleteEdge(target.ID)
		}
	})

	return nil
}
