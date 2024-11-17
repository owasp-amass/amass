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
	start time.Time
	freq  time.Duration
	done  chan struct{}
	cdone chan struct{}
	cache repository.Repository
	db    repository.Repository
	queue queue.Queue
}

func New(database repository.Repository, done chan struct{}) (*Cache, error) {
	if db := assetdb.New(sqlrepo.SQLiteMemory, ""); db != nil {
		c := &Cache{
			start: time.Now(),
			freq:  10 * time.Minute,
			done:  done,
			cdone: make(chan struct{}, 1),
			cache: db.Repo,
			db:    database,
			queue: queue.NewQueue(),
		}

		go c.processDBCallbacks()
		return c, nil
	}
	return nil, errors.New("failed to create the cache repository")
}

// StartTime returns the time that the cache was created.
func (c *Cache) StartTime() time.Time {
	return c.start
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

	close(c.cdone)
	for {
		if c.queue.Empty() {
			break
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

// GetDBType implements the Repository interface.
func (c *Cache) GetDBType() string {
	return c.db.GetDBType()
}

func (c *Cache) appendToDBQueue(callback func()) {
	select {
	case <-c.done:
		return
	case <-c.cdone:
		return
	default:
	}
	c.queue.Append(callback)
}

func (c *Cache) processDBCallbacks() {
loop:
	for {
		select {
		case <-c.done:
			break loop
		case <-c.cdone:
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
	// drain the callback queue of all remaining elements
	c.queue.Process(func(data interface{}) {})
}
