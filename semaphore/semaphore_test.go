// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package semaphore

import (
	"testing"
	"time"
)

func TestSimpleSemaphore(t *testing.T) {
	sem := NewSimpleSemaphore(3)

	sem.Acquire(3)
	sem.Release(3)

	if !sem.TryAcquire(3) {
		t.Errorf("Failed to acquire the semaphore when it should be available")
	}
	sem.Release(3)

	sem.Acquire(1)
	if sem.TryAcquire(3) {
		t.Errorf("Acquired the semaphore when it should not be available")
	}
	sem.Release(1)

	sem.Stop()
}

func TestTimedSemaphore(t *testing.T) {
	sem := NewTimedSemaphore(3, 250*time.Millisecond)

	sem.Acquire(3)
	sem.Release(3)

	if sem.TryAcquire(3) {
		t.Errorf("Acquired the semaphore when it should not yet be available")
	}
	time.Sleep(time.Second)

	sem.Acquire(3)
	sem.Release(3)
	time.Sleep(time.Second)

	if !sem.TryAcquire(3) {
		t.Errorf("Failed to acquire the semaphore when it should be available")
	}
	sem.Release(3)
	time.Sleep(time.Second)

	sem.Acquire(1)
	if sem.TryAcquire(3) {
		t.Errorf("Acquired the semaphore when it should not be available")
	}
	sem.Release(1)

	sem.Stop()
	time.Sleep(time.Second)
}
