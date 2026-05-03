// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package backlogdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

var (
	ErrEmptyEntityID = errors.New("backlog: empty entity id")
)

// Claim represents a leased backlog item.
type Claim struct {
	EntityID string
}

// Has reports whether entity_id exists in the backlog (any state).
func (b *BacklogDB) Has(ctx context.Context, entityID string) (bool, error) {
	b.Lock()
	defer b.Unlock()

	if entityID == "" {
		return false, nil
	}
	var one int
	err := b.db.QueryRowContext(ctx,
		`SELECT 1 FROM backlog_items WHERE entity_id = ? LIMIT 1`,
		entityID,
	).Scan(&one)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Enqueue inserts a new queued item if it does not already exist.
// If entity_id already exists, it sets the state to queued.
func (b *BacklogDB) Enqueue(ctx context.Context, atype oam.AssetType, entityID string) error {
	b.Lock()
	defer b.Unlock()

	if entityID == "" {
		return ErrEmptyEntityID
	}
	t := nowUnix()
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO backlog_items(created_at, updated_at, etype, entity_id, state, lease_until)
		VALUES(?, ?, ?, ?, ?, 0)
		ON CONFLICT(entity_id) DO UPDATE SET
			updated_at  = excluded.updated_at,
			state       = ?,
			lease_owner = NULL,
			lease_until = 0`,
		t, t, string(atype), entityID, StateQueued, StateQueued,
	)
	return err
}

// EnqueueDone inserts an item and marks it done (or updates existing row to done).
func (b *BacklogDB) EnqueueDone(ctx context.Context, atype oam.AssetType, entityID string) error {
	b.Lock()
	defer b.Unlock()

	if entityID == "" {
		return ErrEmptyEntityID
	}
	t := nowUnix()
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO backlog_items(created_at, updated_at, etype, entity_id, state, lease_until)
		VALUES(?, ?, ?, ?, ?, 0)
		ON CONFLICT(entity_id) DO UPDATE SET
			updated_at  = excluded.updated_at,
			state       = ?,
			lease_owner = NULL,
			lease_until = 0`,
		t, t, string(atype), entityID, StateDone, StateDone,
	)
	return err
}

// ClaimNext leases up to n eligible items for an asset type.
// Eligibility:
// - state=queued
// - OR state=leased AND lease_until <= now (expired lease)
//
// The claim is atomic: it runs in a single transaction with BEGIN IMMEDIATE
// and updates selected rows to (state=leased, lease_owner=owner, lease_until=now+ttl).
func (b *BacklogDB) ClaimNext(ctx context.Context, atype oam.AssetType, owner string, n int, ttl time.Duration) ([]Claim, error) {
	b.Lock()
	defer b.Unlock()

	if n <= 0 {
		return nil, nil
	}
	if owner == "" {
		owner = "default"
	}

	now := nowUnix()
	key := string(atype)
	leaseUntil := now + int64(ttl.Seconds())
	if ttl <= 0 {
		ttl := 30 * time.Second
		leaseUntil = now + int64(ttl.Seconds())
	}

	// IMPORTANT: Use a single connection + explicit BEGIN IMMEDIATE to avoid
	// "cannot start a transaction within a transaction" and to make claim atomic.
	conn, err := b.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Begin immediate transaction
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE;`); err != nil {
		return nil, err
	}

	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK;`)
		}
	}()

	var rows *sql.Rows
	if ttl <= 0 {
		rows, err = conn.QueryContext(ctx, `
			SELECT id, entity_id
			FROM backlog_items
			WHERE etype = ?
			AND state = ?
			ORDER BY created_at ASC
			LIMIT ?`,
			key, StateQueued, n,
		)
	} else {
		rows, err = conn.QueryContext(ctx, `
			SELECT id, entity_id
			FROM backlog_items
			WHERE etype = ?
			AND (
					state = ?
					OR (state = ? AND lease_until <= ?)
				)
			ORDER BY created_at ASC
			LIMIT ?`,
			key, StateQueued, StateLeased, now, n,
		)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	var out []Claim
	for rows.Next() {
		var id int64
		var eid string
		if err := rows.Scan(&id, &eid); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		out = append(out, Claim{EntityID: eid})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		if _, err := conn.ExecContext(ctx, `COMMIT;`); err != nil {
			return nil, err
		}
		committed = true
		return nil, nil
	}

	inClause, args, err := makeInClause(ids)
	if err != nil {
		return nil, err
	}

	q := fmt.Sprintf(`
		UPDATE backlog_items
		SET state = ?, lease_owner = ?, lease_until = ?, updated_at = ?
		WHERE id IN (%s)`, inClause)

	updateArgs := []any{StateLeased, owner, leaseUntil, now}
	updateArgs = append(updateArgs, args...)

	if _, err := conn.ExecContext(ctx, q, updateArgs...); err != nil {
		return nil, err
	}

	if _, err := conn.ExecContext(ctx, `COMMIT;`); err != nil {
		return nil, err
	}
	committed = true

	return out, nil
}

// Ack marks a leased item done. If owner is non-empty, it enforces ownership.
func (b *BacklogDB) Ack(ctx context.Context, entityID string, owner string) error {
	b.Lock()
	defer b.Unlock()

	if entityID == "" {
		return ErrEmptyEntityID
	}
	now := nowUnix()

	var (
		res sql.Result
		err error
	)

	if owner != "" {
		res, err = b.db.ExecContext(ctx, `
			UPDATE backlog_items
			SET state = ?, lease_owner = NULL, lease_until = 0, updated_at = ?
			WHERE entity_id = ? AND state = ? AND lease_owner = ?`,
			StateDone, now, entityID, StateLeased, owner,
		)
	} else {
		res, err = b.db.ExecContext(ctx, `
			UPDATE backlog_items
			SET state = ?, lease_owner = NULL, lease_until = 0, updated_at = ?
			WHERE entity_id = ?`,
			StateDone, now, entityID,
		)
	}
	if err != nil {
		return err
	}

	// Optional: enforce that an owned ack actually matched.
	if owner != "" {
		aff, _ := res.RowsAffected()
		if aff == 0 {
			return errors.New("backlog: ack affected 0 rows (owner mismatch or not leased)")
		}
	}
	return nil
}

// Release returns a leased item back to queued (e.g., when admission fails/backpressure).
// If owner is non-empty, it enforces ownership.
func (b *BacklogDB) Release(ctx context.Context, entityID string, owner string) error {
	b.Lock()
	defer b.Unlock()

	if entityID == "" {
		return ErrEmptyEntityID
	}
	now := nowUnix()

	if owner != "" {
		_, err := b.db.ExecContext(ctx, `
			UPDATE backlog_items
			SET state = ?, lease_owner = NULL, lease_until = 0, updated_at = ?
			WHERE entity_id = ? AND state = ? AND lease_owner = ?`,
			StateQueued, now, entityID, StateLeased, owner,
		)
		return err
	}

	_, err := b.db.ExecContext(ctx, `
		UPDATE backlog_items
		SET state = ?, lease_owner = NULL, lease_until = 0, updated_at = ?
		WHERE entity_id = ? AND state = ?`,
		StateQueued, now, entityID, StateLeased,
	)
	return err
}

// RequeueExpired is optional; ClaimNext already treats expired leases as eligible.
// This can be useful if you want to periodically normalize state.
func (b *BacklogDB) RequeueExpired(ctx context.Context) error {
	b.Lock()
	defer b.Unlock()

	now := nowUnix()
	_, err := b.db.ExecContext(ctx, `
		UPDATE backlog_items
		SET state = ?, lease_owner = NULL, lease_until = 0, updated_at = ?
		WHERE state = ? AND lease_until <= ?`,
		StateQueued, now, StateLeased, now,
	)
	return err
}

// Delete removes an item regardless of state.
func (b *BacklogDB) Delete(ctx context.Context, entityID string) error {
	b.Lock()
	defer b.Unlock()

	if entityID == "" {
		return ErrEmptyEntityID
	}
	_, err := b.db.ExecContext(ctx, `DELETE FROM backlog_items WHERE entity_id = ?`, entityID)
	return err
}

// Counts returns counts of queued/leased/done for a given asset type.
// Useful for scaling heuristics.
func (b *BacklogDB) Counts(ctx context.Context, atype oam.AssetType) (queued, leased, done int64, err error) {
	b.Lock()
	defer b.Unlock()

	row := b.db.QueryRowContext(ctx, `
		SELECT
		  COALESCE(SUM(CASE WHEN state = ? THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN state = ? THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN state = ? THEN 1 ELSE 0 END), 0)
		FROM backlog_items
		WHERE etype = ?`,
		StateQueued, StateLeased, StateDone, string(atype),
	)
	err = row.Scan(&queued, &leased, &done)
	return
}
