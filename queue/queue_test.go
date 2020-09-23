// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/OWASP/Amass/v3/stringset"
)

func TestAppend(t *testing.T) {
	queue := NewQueue()

	queue.Append("testing")
	if queue.Empty() || queue.Len() == 0 {
		t.Errorf("The element was not appended to the queue")
	}

	if e, _ := queue.Next(); e != "testing" {
		t.Errorf("The element was appended as %s instead of 'testing'", e.(string))
	}
}

func TestSendSignal(t *testing.T) {
	queue := NewQueue()

	queue.SendSignal()
	select {
	case <-queue.Signal:
	default:
		t.Errorf("Explicitly calling SendSignal did not populate the channel")
	}

	queue.Append("element")
	select {
	case <-queue.Signal:
	default:
		t.Errorf("Use of the Append method did not populate the channel")
	}

	queue.SendSignal()
	queue.Next()
	select {
	case <-queue.Signal:
		t.Errorf("Using the Next method on the last element did not empty the channel")
	default:
	}
}

func TestNext(t *testing.T) {
	queue := NewQueue()
	values := []string{"test1", "test2", "test3", "test4"}
	priorities := []int{90, 75, 30, 5}

	for i, v := range values {
		queue.AppendPriority(v, priorities[i])
	}

	for _, v := range values {
		if e, b := queue.Next(); b && e.(string) != v {
			t.Errorf("Returned %s instead of %s", e.(string), v)
		}
	}

	if _, b := queue.Next(); b != false {
		t.Errorf("An empty Queue claimed to return another element")
	}
}

func TestProcess(t *testing.T) {
	queue := NewQueue()
	set := stringset.New("element1", "element2")

	for e := range set {
		queue.Append(e)
	}

	ret := stringset.New()
	queue.Process(func(e interface{}) {
		if s, ok := e.(string); ok {
			ret.Insert(s)
		}
	})

	set.Subtract(ret)
	if set.Len() > 0 {
		t.Errorf("Not all elements of the queue were provided")
	}

	if queue.Len() > 0 {
		t.Errorf("The queue was not empty after executing the Process method")
	}
}

func TestEmpty(t *testing.T) {
	queue := NewQueue()

	if !queue.Empty() {
		t.Errorf("A new Queue did not claim to be empty")
	}

	queue.Append("testing")
	if queue.Empty() {
		t.Errorf("A queue with elements claimed to be empty")
	}
}

func TestLen(t *testing.T) {
	queue := NewQueue()

	if l := queue.Len(); l != 0 {
		t.Errorf("A new Queue returned a length of %d instead of zero", l)
	}

	queue.Append("testing")
	if l := queue.Len(); l != 1 {
		t.Errorf("A Queue with elements returned a length of %d instead of one", l)
	}
}
