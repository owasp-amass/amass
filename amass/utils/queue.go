// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"sync"
)

type queueNode struct {
	Next *queueNode
	Data interface{}
}

// Queue implements a FIFO data structure.
type Queue struct {
	sync.Mutex
	size       int
	head, tail *queueNode
}

// NewQueue returns a Queue FIFO data structure.
func NewQueue() *Queue {
	return new(Queue)
}

// Append adds the data to the end of the Queue.
func (q *Queue) Append(data interface{}) {
	element := new(queueNode)

	q.Lock()
	defer q.Unlock()

	q.size++
	if q.head == nil {
		q.head = element
	}

	end := q.tail
	if end != nil {
		end.Next = element
	}
	q.tail = element
	element.Data = data
}

// Next returns the data at the front of the Queue.
func (q *Queue) Next() (interface{}, bool) {
	q.Lock()
	defer q.Unlock()

	if q.head == nil {
		return nil, false
	}

	q.size--
	element := q.head
	q.head = element.Next
	if q.tail == element {
		q.tail = nil
	}
	element.Next = nil
	return element.Data, true
}

// Empty return true if the Queue is empty.
func (q *Queue) Empty() bool {
	q.Lock()
	defer q.Unlock()

	if q.head == nil {
		return true
	}
	return false
}

// Len returns the current length of the Queue
func (q *Queue) Len() int {
	return q.size
}
