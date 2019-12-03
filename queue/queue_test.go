// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"
)

func TestAppend(t *testing.T) {
	queue := new(Queue)

	queue.Append("testing")
	if queue.Empty() || queue.Len() == 0 {
		t.Errorf("The element was not appended to the queue")
	}

	if e, _ := queue.Next(); e != "testing" {
		t.Errorf("The element was appended as %s instead of 'testing'", e.(string))
	}
}

func TestNext(t *testing.T) {
	queue := new(Queue)
	values := []string{"test1", "test2", "test3"}

	for _, v := range values {
		queue.Append(v)
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

func TestEmpty(t *testing.T) {
	queue := new(Queue)

	if !queue.Empty() {
		t.Errorf("A new Queue did not claim to be empty")
	}

	queue.Append("testing")
	if queue.Empty() {
		t.Errorf("A queue with elements claimed to be empty")
	}
}

func TestLen(t *testing.T) {
	queue := new(Queue)

	if l := queue.Len(); l != 0 {
		t.Errorf("A new Queue returned a length of %d instead of zero", l)
	}

	queue.Append("testing")
	if l := queue.Len(); l != 1 {
		t.Errorf("A Queue with elements returned a length of %d instead of one", l)
	}
}
