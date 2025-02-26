// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package queuedb

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
)

func makeTempDir() (string, error) {
	dir, err := os.MkdirTemp("", fmt.Sprintf("test-%d", rand.Intn(100)))
	if err != nil {
		return "", errors.New("failed to create the temp dir")
	}
	return dir, nil
}

func TestNewQueueDB(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	assert.NotNil(t, queueDB, "QueueDB should not be nil")
	defer queueDB.Close()

	found := queueDB.db.Migrator().HasTable(&Element{})
	assert.True(t, found, "Element table should exist")
	found = queueDB.db.Migrator().HasIndex(&Element{}, "idx_created_at")
	assert.True(t, found, "Index idx_created_at should exist")
	found = queueDB.db.Migrator().HasIndex(&Element{}, "idx_etype")
	assert.True(t, found, "Index idx_etype should exist")
	found = queueDB.db.Migrator().HasIndex(&Element{}, "idx_entity_id")
	assert.True(t, found, "Index idx_entity_id should exist")
	found = queueDB.db.Migrator().HasIndex(&Element{}, "idx_processed")
	assert.True(t, found, "Index idx_processed should exist")
}

func TestHas(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid := "entity1"
	assert.False(t, queueDB.Has(eid), "The element should not be in the database")

	err = queueDB.Append(oam.FQDN, eid)
	assert.NoError(t, err)
	assert.True(t, queueDB.Has(eid), "The element should be in the database")

	err = queueDB.Delete(eid)
	assert.NoError(t, err)
	assert.False(t, queueDB.Has(eid), "The element should be deleted from the database")
}

func TestAppend(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid := "entity1"
	err = queueDB.Append(oam.FQDN, eid)
	assert.NoError(t, err)

	var element Element
	err = queueDB.db.Where("entity_id = ?", eid).First(&element).Error
	assert.NoError(t, err)
	assert.Equal(t, eid, element.EntityID, "The entity ID should match")
	assert.Equal(t, string(oam.FQDN), element.Type, "The asset type should match")
	assert.False(t, element.Processed, "The processed flag should be false")
}

func TestNext(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid1 := "entity1"
	eid2 := "entity2"
	err = queueDB.Append(oam.FQDN, eid1)
	assert.NoError(t, err)
	err = queueDB.Append(oam.FQDN, eid2)
	assert.NoError(t, err)

	entities, err := queueDB.Next(oam.FQDN, 2)
	assert.NoError(t, err)
	assert.Len(t, entities, 2, "Should return two entities")
	assert.Equal(t, eid1, entities[0])
	assert.Equal(t, eid2, entities[1])
}

func TestNextWithProcessed(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid1 := "entity1"
	eid2 := "entity2"
	err = queueDB.Append(oam.FQDN, eid1)
	assert.NoError(t, err)
	err = queueDB.Append(oam.FQDN, eid2)
	assert.NoError(t, err)

	err = queueDB.Processed(eid1)
	assert.NoError(t, err)

	entities, err := queueDB.Next(oam.FQDN, 2)
	assert.NoError(t, err)
	assert.Len(t, entities, 1, "Should return one entity")
	assert.Equal(t, eid2, entities[0])
}

func TestNextWithMultipleTypes(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid1 := "entity1"
	eid2 := "entity2"
	eid3 := "entity3"
	err = queueDB.Append(oam.FQDN, eid1)
	assert.NoError(t, err)
	err = queueDB.Append(oam.IPAddress, eid2)
	assert.NoError(t, err)
	err = queueDB.Append(oam.FQDN, eid3)
	assert.NoError(t, err)

	entitiesFQDN, err := queueDB.Next(oam.FQDN, 1)
	assert.NoError(t, err)
	assert.Len(t, entitiesFQDN, 1, "Should return one entity for FQDN")
	assert.Equal(t, eid1, entitiesFQDN[0])

	entitiesIPv4, err := queueDB.Next(oam.IPAddress, 1)
	assert.NoError(t, err)
	assert.Len(t, entitiesIPv4, 1, "Should return one entity for IPv4")
	assert.Equal(t, eid2, entitiesIPv4[0])

	entitiesFQDN2, err := queueDB.Next(oam.FQDN, 3)
	assert.NoError(t, err)
	assert.Len(t, entitiesFQDN2, 2, "Should return two entities for FQDN")
	assert.Equal(t, eid1, entitiesFQDN2[0])
	assert.Equal(t, eid3, entitiesFQDN2[1])

	entitiesIPv42, err := queueDB.Next(oam.IPAddress, 3)
	assert.NoError(t, err)
	assert.Len(t, entitiesIPv42, 1, "Should return one entity for IPv4")
	assert.Equal(t, eid2, entitiesIPv42[0])
}

func TestProcessed(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid := "entity1"
	err = queueDB.Append(oam.FQDN, eid)
	assert.NoError(t, err)

	err = queueDB.Processed(eid)
	assert.NoError(t, err)

	var element Element
	err = queueDB.db.Where("entity_id = ?", eid).First(&element).Error
	assert.NoError(t, err)
	assert.True(t, element.Processed, "The processed flag should be true")
}

func TestDelete(t *testing.T) {
	dir, err := makeTempDir()
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, "test.sqlite")
	queueDB, err := NewQueueDB(dbPath)
	assert.NoError(t, err)
	defer queueDB.Close()

	eid := "entity1"
	err = queueDB.Append(oam.FQDN, eid)
	assert.NoError(t, err)
	assert.True(t, queueDB.Has(eid), "The element should be in the database")

	err = queueDB.Delete(eid)
	assert.NoError(t, err)
	assert.False(t, queueDB.Has(eid), "The element should be deleted from the database")
}
