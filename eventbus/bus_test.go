// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package eventbus

import (
	"sync"
	"testing"
	"time"
)

func TestEventBus(t *testing.T) {
	topic := "testing"
	var success, survived bool
	var suclock, surlock sync.Mutex

	bus := NewEventBus()

	fn1 := func(v bool) {
		suclock.Lock()
		success = v
		suclock.Unlock()
	}

	fn2 := func(v bool) {
		surlock.Lock()
		survived = v
		surlock.Unlock()
	}

	bus.Subscribe(topic, fn1)
	bus.Subscribe(topic, fn2)
	defer bus.Unsubscribe(topic, fn2)

	bus.Publish(topic, true)
	time.Sleep(time.Second)

	suclock.Lock()
	s := success
	suclock.Unlock()
	if !s {
		t.Errorf("The callback was not executed for the subscribed topic")
	}

	bus.Publish(topic, false)
	time.Sleep(time.Second)
	bus.Unsubscribe(topic, fn1)

	bus.Publish(topic, true)
	time.Sleep(time.Second)

	suclock.Lock()
	s = success
	suclock.Unlock()
	if success {
		t.Errorf("The callback was executed for the unsubscribed topic")
	}

	surlock.Lock()
	s = survived
	surlock.Unlock()
	if !s {
		t.Errorf("The second callback was removed during the execution of unsubscribe")
	}

	bus.Stop()
	time.Sleep(time.Second)
}
