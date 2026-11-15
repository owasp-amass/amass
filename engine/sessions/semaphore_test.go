// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"sync"
	"testing"
	"time"
)

func acquired(ss *sessSemaphore, within time.Duration) bool {
	done := make(chan struct{})
	go func() {
		ss.Acquire()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// With every slot held, a caller waits, and a release lets it in: waiting
// must not keep the holders from releasing.
func TestSessSemaphoreReleaseWakesAWaiter(t *testing.T) {
	ss := NewSessSemaphore(2)
	ss.Acquire()
	ss.Acquire()

	done := make(chan struct{})
	go func() {
		ss.Acquire()
		close(done)
	}()

	// Let the waiter block before the release.
	time.Sleep(50 * time.Millisecond)
	released := make(chan struct{})
	go func() {
		ss.Release()
		close(released)
	}()

	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("a release blocked while another caller waited for a slot: the session deadlocks")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting caller never got the released slot")
	}
}

// A session's limit changes as other sessions start and end; callers
// waiting on the old limit move to the new one.
func TestSessSemaphoreResize(t *testing.T) {
	ss := NewSessSemaphore(1)
	ss.Acquire()

	done := make(chan struct{})
	go func() {
		ss.Acquire()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	ss.resize(3) // another session ended
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a caller waiting on the old limit was not moved to the new one")
	}

	// Two are held of three: one more fits, the next waits.
	if !acquired(ss, time.Second) {
		t.Fatal("the larger limit did not admit another caller")
	}
	if acquired(ss, 100*time.Millisecond) {
		t.Fatal("more callers than the limit were admitted")
	}

	// Shrinking below what is held admits nobody until enough are released.
	ss2 := NewSessSemaphore(4)
	for range 3 {
		ss2.Acquire()
	}

	ss2.resize(2)
	if acquired(ss2, 100*time.Millisecond) {
		t.Fatal("a caller was admitted while more than the new limit were held")
	}
}

func TestSessSemaphoreConcurrentUse(t *testing.T) {
	ss := NewSessSemaphore(5)

	var mu sync.Mutex
	var inUse, most int
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ss.Acquire()
				mu.Lock()
				inUse++
				most = max(most, inUse)
				mu.Unlock()

				time.Sleep(time.Millisecond)
				mu.Lock()
				inUse--
				mu.Unlock()
				ss.Release()
			}
			if i%10 == 0 {
				ss.resize(5)
			}
		}()
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent callers deadlocked")
	}
	if most > 5 {
		t.Errorf("%d callers held slots at once, more than the limit of 5", most)
	}
}

func TestSessionConnLimit(t *testing.T) {
	for sessions, want := range map[int]int{0: 500, 1: 500, 5: 100, 1000: 1} {
		if got := sessionConnLimit(sessions); got != want {
			t.Errorf("sessionConnLimit(%d) = %d, want %d", sessions, got, want)
		}
	}
}
