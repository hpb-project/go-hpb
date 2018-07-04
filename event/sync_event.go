// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

package event

import (
    "container/list"
    "errors"
    "sync"
)

type EventType int16

type Subscriber chan interface{}

type EleType struct {
    eChan Subscriber
}

type Subscribers struct {
    submap map[Subscriber]*list.Element
    sublist *list.List
}

type SyncEvent struct {
    m   sync.RWMutex
    eventTable map[EventType]Subscribers
}

func NewEvent() *SyncEvent {
    return &SyncEvent{
        eventTable : make(map[EventType]Subscribers),
    }
}

// Subscribe specified event.
func (e *SyncEvent) Subscribe(eventtype EventType) Subscriber {

    e.m.Lock()
    defer e.m.Unlock()

    sub := make(chan interface{})
    subs, ok := e.eventTable[eventtype]
    if !ok {
        subs = Subscribers{
            submap: make(map[Subscriber]*list.Element),
            sublist:list.New(),
        }
        e.eventTable[eventtype] = subs
    }
    subs.sublist.PushBack(EleType{eChan:sub})
    subs.submap[sub]=subs.sublist.Back()
    return sub
}

// UnSubscribe the event and remove the specified subscriber
func (e *SyncEvent) UnSubscribe(eventtype EventType, subscriber Subscriber) (err error) {
    e.m.Lock()
    defer e.m.Unlock()

    subEvent, ok := e.eventTable[eventtype]
    if !ok {
        err = errors.New("No event type.")
        return 
    }
    elem,ok := subEvent.submap[subscriber]
    if !ok {
        err = errors.New("Not subscribe this event.")
        return 
    }
    subEvent.sublist.Remove(elem)
    delete (subEvent.submap, subscriber)
    close(subscriber)
    return
}

//Notify subscribers that Subscribe specified event
func (e *SyncEvent) Notify(eventtype EventType, value interface{}) (err error) {
    e.m.Lock()
    defer e.m.Unlock()

    subs,ok := e.eventTable[eventtype]
    if !ok {
        err = errors.New("No event type.")
        return
    }
    elem := subs.sublist.Front()
    for nil != elem {
        et, ok := elem.Value.(EleType)
        if ok {
            e.NotifyChannel(et.eChan, value)
        }

        elem = elem.Next()
    }
    return 
}

// Notify with subscriber channel.
func (e *SyncEvent) NotifyChannel(subscriber Subscriber, value interface{}) (err error) {
    if subscriber == nil {
        return
    }
    subscriber<-value
    return
}

//Notify all event subscribers
func (e *SyncEvent) NotifyAll(v interface{}) (errs []error) {
    for eventtype,_:=range e.eventTable {
        if err := e.Notify(eventtype, v); err != nil {
            errs = append(errs, err)
        }
    }
    return errs
}
