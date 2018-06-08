package event

import (
	"github.com/orcaman/concurrent-map"
	"github.com/AsynkronIT/protoactor-go/actor"
)

type Event struct {
	Topic   Topic
	Payload interface{}
	Trigger Trigger
}

type Trigger *actor.PID
type Receiver *actor.PID

func RegisterReceiver(name string, fn func(payload interface{})) Receiver {
	receiver, _ := actor.SpawnNamed(actor.FromFunc(func(context actor.Context) {
		fn(context.Message())
	}), name)
	return receiver
}

func RegisterTrigger(name string) Trigger {
	trigger,_ := actor.SpawnNamed(actor.FromFunc(func(context actor.Context) {}),name)
	return trigger
}

var subscribers = cmap.New()

func Subscribe(subscriber *actor.PID, topic Topic) {
	suberSlice, _ := subscribers.Get(string(topic))
	if suberSlice == nil {
		subscribers.Set(string(topic), []*actor.PID{subscriber})
	} else {
		subscribers.Set(string(topic), append(suberSlice.([]*actor.PID), subscriber))
	}
}

func Unsubscribe(suber *actor.PID, topic Topic) {
	tmpslice, ok := subscribers.Get(string(topic))
	if !ok {
		return
	}
	subSlice := tmpslice.([]*actor.PID)
	for i, s := range subSlice {
		if s == suber {
			subscribers.Set(string(topic), append(subSlice[0:i], subSlice[i+1:]...))
			return
		}
	}
}

func FireEvent(event *Event) {
	if event == nil {
		return
	}
	actors, ok := subscribers.Get(string(event.Topic))
	if !ok {
		return
	}
	subSlice := actors.([]*actor.PID)
	for _, subscriber := range subSlice {
		subscriber.Request(event.Payload, event.Trigger)
	}
}
