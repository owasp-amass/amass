// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package queuedb

import (
	"time"

	"github.com/glebarez/sqlite"
	oam "github.com/owasp-amass/open-asset-model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type QueueDB struct {
	db *gorm.DB
}

type Element struct {
	ID        uint64    `gorm:"primaryKey;column:id"`
	CreatedAt time.Time `gorm:"index:idx_created_at,sort:asc;column:created_at"`
	UpdatedAt time.Time
	Type      string `gorm:"index:idx_etype;column:etype"`
	EntityID  string `gorm:"index:idx_entity_id,unique;column:entity_id"`
	Processed bool   `gorm:"index:idx_processed;column:processed"`
}

func NewQueueDB(dbPath string) (*QueueDB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(3)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	err = db.AutoMigrate(&Element{})
	if err != nil {
		return nil, err
	}

	return &QueueDB{db: db}, nil
}

func (r *QueueDB) Close() error {
	if r.db != nil {
		sqlDB, err := r.db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

func (r *QueueDB) Has(eid string) bool {
	var count int64

	err := r.db.Model(&Element{}).Where("entity_id = ?", eid).Count(&count).Error
	if err != nil {
		return false
	}

	return count > 0
}

func (r *QueueDB) Append(atype oam.AssetType, eid string) error {
	return r.db.Create(&Element{
		Type:      string(atype),
		EntityID:  eid,
		Processed: false,
	}).Error
}

func (r *QueueDB) Next(atype oam.AssetType, num int) ([]string, error) {
	var elements []Element
	key := string(atype)

	r.db.Model(&Element{}).Where("etype = ? AND processed = ?",
		key, false).Order("created_at ASC").Limit(num).Find(&elements)

	var results []string
	for _, element := range elements {
		results = append(results, element.EntityID)
	}
	return results, nil
}

func (r *QueueDB) Processed(eid string) error {
	return r.db.Model(&Element{}).Where("entity_id = ?", eid).Update("processed", true).Error
}

func (r *QueueDB) Delete(eid string) error {
	var element Element

	err := r.db.Model(&Element{}).Where("entity_id = ?", eid).Find(&element).Error
	if err != nil {
		return err
	}

	return r.db.Delete(&element).Error
}
