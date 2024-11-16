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
