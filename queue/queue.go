// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"container/heap"
	"sync"
)

// The priority levels for the priority Queue.
const (
	PriorityLow int = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

type queueElement struct {
	Data     interface{}
	priority int
	index    int
}

type priorityQueue []*queueElement

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].priority > pq[j].priority
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	element := x.(*queueElement)
	element.index = n
	*pq = append(*pq, element)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	element := old[n-1]
	old[n-1] = nil     // avoid memory leak
	element.index = -1 // for safety
	*pq = old[:n-1]
	return element
}

// Queue implements a FIFO data structure.
type Queue struct {
	sync.Mutex
	Signal chan struct{}
	queue  priorityQueue
}

// NewQueue return an initialized Queue.
func NewQueue() *Queue {
	return &Queue{Signal: make(chan struct{}, 2)}
}

// Append adds the data to the Queue at priority level PriorityNormal.
func (q *Queue) Append(data interface{}) {
	q.append(data, PriorityNormal)
}

// AppendPriority adds the data to the Queue with respect to priority.
func (q *Queue) AppendPriority(data interface{}, priority int) {
	q.append(data, priority)
}

func (q *Queue) append(data interface{}, priority int) {
	element := new(queueElement)

	element.Data = data
	element.priority = priority
	q.Lock()
	heap.Push(&q.queue, element)
	q.Unlock()
	q.SendSignal()
}

// SendSignal puts an element on the queue signal channel.
func (q *Queue) SendSignal() {
	// Empty the channel
	select {
	case <-q.Signal:
	default:
	}

	q.Signal <- struct{}{}
}

// Next returns the data at the front of the Queue.
func (q *Queue) Next() (interface{}, bool) {
	q.Lock()
	defer q.Unlock()

	var ok bool
	var data interface{}
	if q.queue.Len() > 0 {
		element := heap.Pop(&q.queue).(*queueElement)
		ok = true
		data = element.Data
	}

	return data, ok
}

// Process will execute the callback parameter for each element on the Queue.
func (q *Queue) Process(callback func(interface{})) {
	element, ok := q.Next()

	for ok {
		callback(element)
		element, ok = q.Next()
	}
}

// Empty returns true if the Queue is empty.
func (q *Queue) Empty() bool {
	return q.Len() == 0
}

// Len returns the current length of the Queue
func (q *Queue) Len() int {
	q.Lock()
	defer q.Unlock()

	return q.queue.Len()
}
