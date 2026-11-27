// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package backlogdb

import (
	"context"
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasEnqueueDelete(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-1"
	ok, err := db.Has(ctx, eid)
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	ok, err = db.Has(ctx, eid)
	require.NoError(t, err)
	assert.True(t, ok)

	require.NoError(t, db.Delete(ctx, eid))

	ok, err = db.Has(ctx, eid)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestEnqueueIsIdempotent(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-dup"
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	queued, leased, done, err := db.Counts(ctx, oam.FQDN)
	require.NoError(t, err)
	assert.Equal(t, int64(1), queued)
	assert.Equal(t, int64(0), leased)
	assert.Equal(t, int64(0), done)
}

func TestClaimNextFIFOOrdering(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	e1 := "entity-1"
	e2 := "entity-2"
	e3 := "entity-3"

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, e1))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, e2))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, e3))

	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 2, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 2)

	assert.Equal(t, e1, claims[0])
	assert.Equal(t, e2, claims[1])

	// Remaining claim should be e3
	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 2, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims2, 1)
	assert.Equal(t, e3, claims2[0])
}

func TestClaimNextIsTypeIsolated(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	f1 := "fqdn-1"
	i1 := "ip-1"
	f2 := "fqdn-2"

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, f1))
	require.NoError(t, db.Enqueue(ctx, oam.IPAddress, i1))
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, f2))

	claimsF, err := db.ClaimNext(ctx, oam.FQDN, "owner", 10, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claimsF, 2)
	assert.Equal(t, f1, claimsF[0])
	assert.Equal(t, f2, claimsF[1])

	claimsIP, err := db.ClaimNext(ctx, oam.IPAddress, "owner", 10, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claimsIP, 1)
	assert.Equal(t, i1, claimsIP[0])
}

func TestClaimNextLeasesPreventReclaim(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-lease"
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, eid, claims[0])

	// Claim again immediately: should be empty due to lease
	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, 60*time.Second)
	require.NoError(t, err)
	assert.Len(t, claims2, 0)

	queued, leased, done, err := db.Counts(ctx, oam.FQDN)
	require.NoError(t, err)
	assert.Equal(t, int64(0), queued)
	assert.Equal(t, int64(1), leased)
	assert.Equal(t, int64(0), done)
}

func TestReleaseReturnsToQueuedAndReclaimable(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-release"
	owner := "ownerA"

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	claims, err := db.ClaimNext(ctx, oam.FQDN, owner, 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	require.NoError(t, db.Release(ctx, eid, owner))

	queued, leased, done, err := db.Counts(ctx, oam.FQDN)
	require.NoError(t, err)
	assert.Equal(t, int64(1), queued)
	assert.Equal(t, int64(0), leased)
	assert.Equal(t, int64(0), done)

	// Should be claimable again
	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims2, 1)
	assert.Equal(t, eid, claims2[0])
}

func TestAckMarksDoneAndNotClaimable(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-ack"
	owner := "ownerA"

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	claims, err := db.ClaimNext(ctx, oam.FQDN, owner, 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	require.NoError(t, db.Ack(ctx, eid, owner))

	queued, leased, done, err := db.Counts(ctx, oam.FQDN)
	require.NoError(t, err)
	assert.Equal(t, int64(0), queued)
	assert.Equal(t, int64(0), leased)
	assert.Equal(t, int64(1), done)

	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, 60*time.Second)
	require.NoError(t, err)
	assert.Len(t, claims2, 0)
}

func TestAckWithWrongOwnerFails(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-wrong-owner"
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	// Strict owner mismatch should fail
	err = db.Ack(ctx, eid, "ownerB")
	assert.Error(t, err)

	// But ownerless ack should succeed (if you allow it)
	err = db.Ack(ctx, eid, "")
	assert.NoError(t, err)
}

func TestClaimNextReclaimsExpiredLease(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-expire"
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	// Claim with short TTL
	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 1*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	// Wait for lease to expire
	time.Sleep(1100 * time.Millisecond)

	// Another owner should reclaim it
	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims2, 1)
	assert.Equal(t, eid, claims2[0])
}

func TestDeleteRemovesRegardlessOfState(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eid := "entity-delete"
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, eid))

	// Lease it
	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	require.NoError(t, db.Delete(ctx, eid))

	ok, err := db.Has(ctx, eid)
	require.NoError(t, err)
	assert.False(t, ok)

	queued, leased, done, err := db.Counts(ctx, oam.FQDN)
	require.NoError(t, err)
	assert.Equal(t, int64(0), queued)
	assert.Equal(t, int64(0), leased)
	assert.Equal(t, int64(0), done)
}

func TestCountsMultiState(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// queued: q1,q2
	// leased: l1
	// done: d1
	q1 := "q1"
	q2 := "q2"
	l1 := "l1"
	d1 := "d1"

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, d1))
	done1, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, done1, 1)
	require.NoError(t, db.Ack(ctx, d1, "ownerA"))

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, q1))
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, q2))
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, l1))

	// lease l1
	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 60*time.Second)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	assert.Equal(t, q1, claims[0], "FIFO should lease q1 first")

	// now queued: q2,l1 ; leased: q1 ; done: d1
	queued, leased, done, err := db.Counts(ctx, oam.FQDN)
	require.NoError(t, err)
	assert.Equal(t, int64(2), queued) // q2,l1
	assert.Equal(t, int64(1), leased) // q1
	assert.Equal(t, int64(1), done)   // d1
}

func TestClaimNextWithoutTTLKeepsTheLease(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, "entity-held"))
	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 0)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	time.Sleep(1100 * time.Millisecond)

	// A lease without a time to live does not expire.
	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, time.Second)
	require.NoError(t, err)
	assert.Empty(t, claims2)

	// It returns to the queue only when released.
	require.NoError(t, db.Release(ctx, "entity-held", "ownerA"))
	claims3, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, time.Second)
	require.NoError(t, err)
	require.Len(t, claims3, 1)
}

func TestClaimNextRoundsAShortTTLUp(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, "entity-short"))
	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", 1, 200*time.Millisecond)
	require.NoError(t, err)
	require.Len(t, claims, 1)

	// A lease shorter than a second still lasts until the next second.
	claims2, err := db.ClaimNext(ctx, oam.FQDN, "ownerB", 1, time.Second)
	require.NoError(t, err)
	assert.Empty(t, claims2)
}

func TestClaimNextIsFIFOWithinASecond(t *testing.T) {
	db, _ := openTestBacklog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids := []string{"e5", "e3", "e9", "e1", "e7"}
	for _, id := range ids {
		require.NoError(t, db.Enqueue(ctx, oam.FQDN, id))
	}

	claims, err := db.ClaimNext(ctx, oam.FQDN, "ownerA", len(ids), time.Minute)
	require.NoError(t, err)
	require.Len(t, claims, len(ids))
	for i, c := range claims {
		assert.Equal(t, ids[i], c)
	}
}

// Enqueueing an item again queues it once it is done, and leaves it as it is
// while it is queued or leased.
func TestEnqueueAgainOnlyRequeuesDone(t *testing.T) {
	db, _ := openTestBacklog(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, "e1"))
	claims, err := db.ClaimNext(ctx, oam.FQDN, "owner", 1, time.Minute)
	require.NoError(t, err)
	require.Equal(t, []string{"e1"}, claims)

	require.NoError(t, db.Enqueue(ctx, oam.FQDN, "e1"))
	again, err := db.ClaimNext(ctx, oam.FQDN, "other", 1, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, again, "a leased item was queued again")

	require.NoError(t, db.Ack(ctx, "e1", "owner"))
	require.NoError(t, db.Enqueue(ctx, oam.FQDN, "e1"))
	again, err = db.ClaimNext(ctx, oam.FQDN, "other", 1, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, []string{"e1"}, again, "a done item was not queued again")
}
