// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"errors"
	"path/filepath"

	qdb "github.com/owasp-amass/amass/v4/engine/sessions/queuedb"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type sessionQueue struct {
	session *Session
	db      *qdb.QueueDB
}

func newSessionQueue(s *Session) (*sessionQueue, error) {
	dbfile := filepath.Join(s.TmpDir(), "queue.db")

	db, err := qdb.NewQueueDB(dbfile)
	if err != nil {
		return nil, err
	}

	return &sessionQueue{
		session: s,
		db:      db,
	}, nil
}

func (sq *sessionQueue) Close() error {
	return sq.db.Close()
}

func (sq *sessionQueue) Has(e *dbt.Entity) bool {
	if e == nil || e.ID == "" {
		return false
	}
	return sq.db.Has(e.ID)
}

func (sq *sessionQueue) Append(e *dbt.Entity) error {
	if e == nil {
		return errors.New("entity is nil")
	}
	if e.ID == "" {
		return errors.New("entity ID is empty")
	}
	if e.Asset == nil {
		return errors.New("asset is nil")
	}

	key := e.Asset.AssetType()
	if key == "" {
		return errors.New("asset type is empty")
	}
	return sq.db.Append(key, e.ID)
}

func (sq *sessionQueue) Next(atype oam.AssetType, num int) ([]*dbt.Entity, error) {
	ids, err := sq.db.Next(atype, num)
	if err != nil {
		return nil, err
	}

	var results []*dbt.Entity
	for _, id := range ids {
		if e, err := sq.session.Cache().FindEntityById(id); err == nil {
			results = append(results, e)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no entities found")
	}
	return results, nil
}

func (sq *sessionQueue) Processed(e *dbt.Entity) error {
	if e == nil || e.ID == "" {
		return errors.New("entity is nil or ID is empty")
	}
	return sq.db.Processed(e.ID)
}

func (sq *sessionQueue) Delete(e *dbt.Entity) error {
	if e == nil || e.ID == "" {
		return errors.New("entity is nil or ID is empty")
	}
	return sq.db.Delete(e.ID)
}
