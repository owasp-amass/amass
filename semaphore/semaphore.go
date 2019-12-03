// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package semaphore

import (
	"sync"
	"time"
)

// Semaphore is the interface for the several types of semaphore implemented by Amass.
type Semaphore interface {
	// Acquire blocks until num resource counts have been obtained
	Acquire(num int)

	// TryAcquire attempts to obtain num resource counts without blocking
	TryAcquire(num int) bool

	// Release causes num resource counts to be released
	Release(num int)

	// Releases all resources allocated by the semaphore
	Stop()
}

// SimpleSemaphore implements a synchronization object
// type capable of being a counting semaphore.
type SimpleSemaphore struct {
	c chan struct{}
}

// NewSimpleSemaphore returns a SimpleSemaphore initialized to max resource counts.
func NewSimpleSemaphore(max int) Semaphore {
	sem := &SimpleSemaphore{
		c: make(chan struct{}, max),
	}

	for i := 0; i < max; i++ {
		sem.c <- struct{}{}
	}
	return sem
}

// Acquire blocks until num resource counts have been obtained.
func (s *SimpleSemaphore) Acquire(num int) {
	for i := 0; i < num; i++ {
		<-s.c
	}
}

// TryAcquire attempts to obtain num resource counts without blocking.
// The method returns true when successful in acquiring the resource counts.
func (s *SimpleSemaphore) TryAcquire(num int) bool {
	var count int
loop:
	for i := 0; i < num; i++ {
		select {
		case <-s.c:
			count++
		default:
			break loop
		}
	}

	if count == num {
		return true
	}
	s.Release(count)
	return false
}

// Release causes num resource counts to be released.
func (s *SimpleSemaphore) Release(num int) {
	for i := 0; i < num; i++ {
		s.c <- struct{}{}
	}
}

// Stop implements the Semaphore interface.
func (s *SimpleSemaphore) Stop() {
	return
}

// TimedSemaphore implements a synchronization object
// type capable of being a counting semaphore.
type TimedSemaphore struct {
	c      chan struct{}
	rel    chan int
	del    time.Duration
	done   chan struct{}
	closed sync.Once
}

// NewTimedSemaphore returns a TimedSemaphore initialized to max resource counts
// and delay release frequency.
func NewTimedSemaphore(max int, delay time.Duration) Semaphore {
	sem := &TimedSemaphore{
		c:    make(chan struct{}, max),
		rel:  make(chan int, max),
		del:  delay,
		done: make(chan struct{}),
	}

	for i := 0; i < max; i++ {
		sem.c <- struct{}{}
	}

	go sem.processReleases()
	return sem
}

// Acquire blocks until num resource counts have been obtained.
func (t *TimedSemaphore) Acquire(num int) {
	for i := 0; i < num; i++ {
		<-t.c
	}
}

// TryAcquire attempts to obtain num resource counts without blocking.
// The method returns true when successful in acquiring the resource counts.
func (t *TimedSemaphore) TryAcquire(num int) bool {
	var count int
loop:
	for i := 0; i < num; i++ {
		select {
		case <-t.c:
			count++
		default:
			break loop
		}
	}

	if count == num {
		return true
	}

	for i := 0; i < count; i++ {
		t.c <- struct{}{}
	}
	return false
}

// Release causes num resource counts to be released.
func (t *TimedSemaphore) Release(num int) {
	t.rel <- num
}

func (t *TimedSemaphore) processReleases() {
	tick := time.NewTicker(t.del)
	defer tick.Stop()

	var rcount int
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			if rcount > 0 {
				t.c <- struct{}{}
				rcount--
			}
		case num := <-t.rel:
			rcount += num
		}
	}
}

// Stop implements the Semaphore interface.
func (t *TimedSemaphore) Stop() {
	t.closed.Do(func() {
		close(t.done)
	})
}
