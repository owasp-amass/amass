package eventbus

import (
	"reflect"
	"sync"

	"github.com/OWASP/Amass/v3/queue"
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

type subReq struct {
	Topic string
	Fn    interface{}
}

type eventbusChans struct {
	Subscribe   chan *subReq
	Unsubscribe chan *subReq
}

// EventBus handles sending and receiving events across Amass.
type EventBus struct {
	channels *eventbusChans
	queues   []*queue.Queue
	done     chan struct{}
	closed   sync.Once
}

// NewEventBus initializes and returns an EventBus object.
func NewEventBus() *EventBus {
	eb := &EventBus{
		channels: &eventbusChans{
			Subscribe:   make(chan *subReq, 10),
			Unsubscribe: make(chan *subReq, 10),
		},
		queues: []*queue.Queue{
			queue.NewQueue(),
			queue.NewQueue(),
			queue.NewQueue(),
		},
		done: make(chan struct{}, 2),
	}

	go eb.processRequests(eb.channels)
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
	eb.channels.Subscribe <- &subReq{
		Topic: topic,
		Fn:    fn,
	}
}

// Unsubscribe deregisters the callback from the channel.
func (eb *EventBus) Unsubscribe(topic string, fn interface{}) {
	eb.channels.Unsubscribe <- &subReq{
		Topic: topic,
		Fn:    fn,
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

type topicEntry struct {
	sync.Mutex
	Topic     string
	Callbacks []reflect.Value
	Queue     *queue.Queue
	Done      chan struct{}
}

func (eb *EventBus) processRequests(chs *eventbusChans) {
	topics := make(map[string]*topicEntry)
	each := func(element interface{}) {
		p := element.(*pubReq)

		if _, ok := topics[p.Topic]; ok {
			topics[p.Topic].Queue.Append(p)
		}
	}
loop:
	for {
		select {
		case <-eb.done:
			for _, topic := range topics {
				close(topic.Done)
			}
			return
		case sub := <-chs.Subscribe:
			if sub.Topic != "" && reflect.TypeOf(sub.Fn).Kind() == reflect.Func {
				if _, found := topics[sub.Topic]; !found {
					topics[sub.Topic] = &topicEntry{
						Topic: sub.Topic,
						Queue: queue.NewQueue(),
						Done:  make(chan struct{}, 2),
					}

					go eb.processTopicEvents(topics[sub.Topic])
				}

				callback := reflect.ValueOf(sub.Fn)
				topics[sub.Topic].Lock()
				topics[sub.Topic].Callbacks = append(topics[sub.Topic].Callbacks, callback)
				topics[sub.Topic].Unlock()
			}
		case unsub := <-chs.Unsubscribe:
			if unsub.Topic != "" && reflect.TypeOf(unsub.Fn).Kind() == reflect.Func {
				callback := reflect.ValueOf(unsub.Fn)

				if _, found := topics[unsub.Topic]; !found {
					continue loop
				}

				topics[unsub.Topic].Lock()
				var channels []reflect.Value
				for _, c := range topics[unsub.Topic].Callbacks {
					if c != callback {
						channels = append(channels, c)
					}
				}
				topics[unsub.Topic].Callbacks = channels
				topics[unsub.Topic].Unlock()
			}
		case <-eb.queues[PriorityLow].Signal:
			eb.queues[PriorityLow].Process(each)
		case <-eb.queues[PriorityHigh].Signal:
			eb.queues[PriorityHigh].Process(each)
		case <-eb.queues[PriorityCritical].Signal:
			eb.queues[PriorityCritical].Process(each)
		}
	}
}

func (eb *EventBus) processTopicEvents(topic *topicEntry) {
	for {
		select {
		case <-topic.Done:
			return
		case <-topic.Queue.Signal:
			topic.Lock()
			callbacks := topic.Callbacks
			topic.Unlock()
			each := func(element interface{}) {
				p := element.(*pubReq)

				for _, cb := range callbacks {
					cb.Call(p.Args)
				}
			}

			topic.Queue.Process(each)
		}
	}
}
