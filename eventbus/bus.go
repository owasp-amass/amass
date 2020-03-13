package eventbus

import (
	"reflect"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/semaphore"
)

// The priority levels for event bus messages.
const (
	PriorityLow int = iota
	PriorityHigh
	PriorityCritical
)

type pubReq struct {
	Topic string
	Args  []reflect.Value
}

// EventBus handles sending and receiving events across Amass.
type EventBus struct {
	sync.Mutex
	topics map[string][]reflect.Value
	max    semaphore.Semaphore
	queues []*queue.Queue
	done   chan struct{}
	closed sync.Once
}

// NewEventBus initializes and returns an EventBus object.
func NewEventBus(max int) *EventBus {
	eb := &EventBus{
		topics: make(map[string][]reflect.Value),
		max:    semaphore.NewSimpleSemaphore(max),
		queues: []*queue.Queue{
			new(queue.Queue),
			new(queue.Queue),
			new(queue.Queue),
		},
		done: make(chan struct{}, 2),
	}

	go eb.processRequests()
	return eb
}

// Stop prevents any additional requests from being sent.
func (eb *EventBus) Stop() {
	eb.closed.Do(func() {
		close(eb.done)
	})
}

// Subscribe registers callback to be executed for all requests on the channel.
func (eb *EventBus) Subscribe(topic string, fn interface{}) {
	if topic != "" && reflect.TypeOf(fn).Kind() == reflect.Func {
		callback := reflect.ValueOf(fn)

		eb.Lock()
		eb.topics[topic] = append(eb.topics[topic], callback)
		eb.Unlock()
	}
}

// Unsubscribe deregisters the callback from the channel.
func (eb *EventBus) Unsubscribe(topic string, fn interface{}) {
	if topic != "" && reflect.TypeOf(fn).Kind() == reflect.Func {
		callback := reflect.ValueOf(fn)

		eb.Lock()
		defer eb.Unlock()

		var channels []reflect.Value
		for _, c := range eb.topics[topic] {
			if c != callback {
				channels = append(channels, c)
			}
		}

		eb.topics[topic] = channels
	}
}

// Publish sends req on the channel labeled with name.
func (eb *EventBus) Publish(topic string, priority int, args ...interface{}) {
	if topic != "" && priority >= PriorityLow && priority <= PriorityCritical {
		passedArgs := make([]reflect.Value, 0)

		for _, arg := range args {
			passedArgs = append(passedArgs, reflect.ValueOf(arg))
		}

		eb.queues[priority].Append(&pubReq{
			Topic: topic,
			Args:  passedArgs,
		})
	}
}

func (eb *EventBus) processRequests() {
	curIdx := 0
	maxIdx := 6
	delays := []int{10, 25, 50, 75, 100, 150, 250}

	for {
		select {
		case <-eb.done:
			return
		default:
			var found bool
			var element interface{}
			// Pull from the critical queue first
			for p := PriorityCritical; p >= PriorityLow; p-- {
				element, found = eb.queues[p].Next()
				if found {
					break
				}
			}

			if !found {
				if curIdx < maxIdx {
					curIdx++
				}
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				continue
			}

			curIdx = 0
			p := element.(*pubReq)

			eb.Lock()
			callbacks, found := eb.topics[p.Topic]
			eb.Unlock()
			if !found {
				continue
			}

			for _, cb := range callbacks {
				eb.max.Acquire(1)
				go eb.execute(cb, p.Args)
			}
		}
	}
}

func (eb *EventBus) execute(callback reflect.Value, args []reflect.Value) {
	defer eb.max.Release(1)

	callback.Call(args)
}
