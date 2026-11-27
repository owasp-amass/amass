// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"fmt"
	"testing"
	"time"
)

func receive(t *testing.T, ch <-chan *string, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	timeout := time.After(5 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed after %d of %d messages", i, n)
			}
			got[*msg]++
		case <-timeout:
			t.Fatalf("received %d of %d messages", i, n)
		}
	}
	return got
}

func TestPublishReachesEverySubscriber(t *testing.T) {
	l := NewLogger()
	defer l.Close()

	a, b := l.Subscribe(), l.Subscribe()
	l.Publish("one")
	if _, err := l.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	for name, ch := range map[string]<-chan *string{"a": a, "b": b} {
		if got := receive(t, ch, 2); got["one"] != 1 || got["two"] != 1 {
			t.Errorf("subscriber %s received %v", name, got)
		}
	}
}

// A message published before anyone subscribes is dropped.
func TestPublishWithoutSubscribers(t *testing.T) {
	l := NewLogger()
	defer l.Close()

	l.Publish("lost")
	ch := l.Subscribe()
	l.Publish("kept")
	if got := receive(t, ch, 1); got["kept"] != 1 {
		t.Errorf("received %v, want only the message published after subscribing", got)
	}
}

// A subscriber that falls behind its buffer still receives every message.
func TestSlowSubscriber(t *testing.T) {
	l := NewLogger()
	defer l.Close()

	ch := l.Subscribe()
	const n = 250
	for i := 0; i < n; i++ {
		l.Publish(fmt.Sprintf("msg %d", i))
	}
	if got := receive(t, ch, n); len(got) != n {
		t.Errorf("received %d distinct messages, want %d", len(got), n)
	}
}

func TestCloseClosesSubscriptions(t *testing.T) {
	l := NewLogger()
	ch := l.Subscribe()
	l.Close()

	select {
	case _, ok := <-ch:
		if ok {
			// a message may still be buffered; the channel must close after it
			for range ch {
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription was not closed")
	}
}

// Publishing while subscribers come and go is safe (run with -race).
func TestConcurrentSubscribeAndPublish(t *testing.T) {
	l := NewLogger()
	defer l.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			l.Publish("tick")
		}
	}()
	for i := 0; i < 10; i++ {
		_ = l.Subscribe()
	}
	<-done
}
