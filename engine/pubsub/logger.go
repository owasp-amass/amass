// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"sync"

	"github.com/caffix/queue"
)

// Logger provides functionality for logging and subscribing to logs.
type Logger struct {
	sync.Mutex
	done       chan struct{}  // Channel to signal closure of the logger.
	q          queue.Queue    // Embeds a queue for managing log messages.
	subscribed []chan *string // Channels used to communicate log messages.
}

// NewLogger initializes and returns a new instance of Logger.
func NewLogger() *Logger {
	l := &Logger{
		done:       make(chan struct{}),
		q:          queue.NewQueue(),
		subscribed: make([]chan *string, 0), // Initialize the slice for subscribed channels.
	}
	go l.broadcastMessages()
	return l
}

// Publish sends a log message to the logger.
func (l *Logger) Publish(msg string) {
	if len(l.subscribed) > 0 {
		l.q.Append(msg)
	}
}

// Write allows the Logger to be used as a Writer and in structured logging.
func (l *Logger) Write(p []byte) (n int, err error) {
	l.Publish(string(p))
	return len(p), nil
}

// Subscribe provides a read-only channel to receive log messages.
// This allows external components to "listen" for new logs.
func (l *Logger) Subscribe() <-chan *string {
	l.Lock()
	defer l.Unlock()

	ch := make(chan *string, 100)
	l.subscribed = append(l.subscribed, ch)
	return ch
}

func (l *Logger) Close() {
	close(l.done)
	// drain the queue
	l.q.Process(func(any) {})

	l.Lock()
	defer l.Unlock()

	// Close all subscribed channels to signal that no more messages will be sent.
	for _, ch := range l.subscribed {
		close(ch)
	}
}

func (l *Logger) broadcastMessages() {
	for {
		select {
		case <-l.done:
			return
		case <-l.q.Signal():
		}

		l.q.Process(l.msgToSubscribers)
	}
}

func (l *Logger) msgToSubscribers(e any) {
	msg, ok := e.(string)
	if !ok {
		return
	}

	l.Lock()
	defer l.Unlock()

	for _, ch := range l.subscribed {
		select {
		case <-l.done:
			return
		case ch <- &msg:
		default:
			go l.send(ch, msg)
		}
	}
}

func (l *Logger) send(ch chan *string, msg string) {
	ch <- &msg
}
