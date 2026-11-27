// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestProbePacerSpacesOneHost(t *testing.T) {
	p := NewProbePacer(40*time.Millisecond, 0)

	start := time.Now()
	for range 4 {
		if err := p.Pace(context.Background(), "192.0.2.1"); err != nil {
			t.Fatalf("pacing returned an error: %v", err)
		}
	}

	// The first probe is immediate; three more are each 40ms apart.
	if elapsed := time.Since(start); elapsed < 110*time.Millisecond {
		t.Errorf("four paced probes to one host took %v, expected at least ~120ms", elapsed)
	}
}

func TestProbePacerDoesNotWaitAcrossHosts(t *testing.T) {
	p := NewProbePacer(time.Second, 0)

	start := time.Now()
	for _, host := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"} {
		if err := p.Pace(context.Background(), host); err != nil {
			t.Fatalf("pacing returned an error: %v", err)
		}
	}

	// The first probe to each host is immediate, so different hosts do not
	// wait on one another.
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("one probe to each of four hosts took %v, expected near zero", elapsed)
	}
}

func TestProbePacerStopsWhenContextCancelled(t *testing.T) {
	p := NewProbePacer(time.Hour, 0)

	// Reserve the host so the next probe would wait an hour.
	if err := p.Pace(context.Background(), "192.0.2.1"); err != nil {
		t.Fatalf("the first probe should not wait: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if err := p.Pace(ctx, "192.0.2.1"); err == nil {
		t.Fatal("pacing should return the context error when cancelled while waiting")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a cancelled probe waited %v instead of returning promptly", elapsed)
	}
}

func TestProbePacerConcurrentHostIsSerialized(t *testing.T) {
	p := NewProbePacer(15*time.Millisecond, 0)

	start := time.Now()
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Pace(context.Background(), "198.51.100.9")
		}()
	}

	wg.Wait()

	// Six concurrent probes to one host are spread 15ms apart, so the last
	// leaves no sooner than five intervals after the first.
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Errorf("six concurrent probes to one host took %v, expected them spread out", elapsed)
	}
}

func TestNilProbePacerAndEmptyHost(t *testing.T) {
	var p *ProbePacer
	if err := p.Pace(context.Background(), "192.0.2.1"); err != nil {
		t.Errorf("a nil pacer should not wait or error: %v", err)
	}

	p = NewProbePacer(0, time.Second)
	if p != nil {
		t.Error("a pace of zero should disable pacing")
	}

	p = NewProbePacer(time.Hour, 0)
	start := time.Now()
	if err := p.Pace(context.Background(), ""); err != nil {
		t.Errorf("an empty host should not wait or error: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("an empty host should not be paced")
	}
}

func TestProbePacerBoundsRememberedHosts(t *testing.T) {
	p := NewProbePacer(time.Nanosecond, 0)

	for i := range maxPacedHosts + 2000 {
		host := "203.0.113." + itoa(i)
		if err := p.Pace(context.Background(), host); err != nil {
			t.Fatalf("pacing returned an error: %v", err)
		}
	}

	p.mu.Lock()
	remembered := len(p.next)
	p.mu.Unlock()
	if remembered > maxPacedHosts {
		t.Errorf("the pacer remembers %d hosts, more than the %d bound", remembered, maxPacedHosts)
	}
}

func TestProbePacerFromContext(t *testing.T) {
	if ProbePacerFrom(context.Background()) != nil {
		t.Error("a context with no pacer should return nil")
	}

	p := NewProbePacer(time.Millisecond, 0)
	ctx := WithProbePacer(context.Background(), p)
	if ProbePacerFrom(ctx) != p {
		t.Error("the pacer carried on the context was not returned")
	}
}

// itoa avoids a strconv import for the bound test's host names.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}

	return string(b)
}
