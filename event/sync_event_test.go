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
    "fmt"
    "time"
    "testing"
)

func routine_exit(v int) {
    fmt.Println("routine exit ", v)
}

func TestNewEvent(t *testing.T) {
    la_event := NewEvent()
    fmt.Println("Subscribe...")
    s_1_1 := la_event.Subscribe(1)
    s_1_2 := la_event.Subscribe(1)
    s_2_1 := la_event.Subscribe(2)
    s_2_2 := la_event.Subscribe(2)
    go func (){
        defer routine_exit(1)
        for {
            val:= <-s_1_1
            if val == nil {
                fmt.Println("channel closed.")
                return 
            }
            if vint, ok := val.(int); ok {
                fmt.Println("sub1 chan, value = ", vint)
            }
        }
    }()
    go func (){
        defer routine_exit(2)
        for {
            val:= <-s_1_2
            if val == nil {
                fmt.Println("channel closed.")
                return 
            }
            if vint, ok := val.(int); ok {
                fmt.Println("sub2 chan, value = ", vint)
            }
        }
    }()
    go func (){
        defer routine_exit(3)
        for {
            val:= <-s_2_1
            if val == nil {
                fmt.Println("channel closed.")
                return 
            }
            if vint, ok := val.(int); ok {
                fmt.Println("sub1 chan, value = ", vint)
            }
        }
    }()
    go func (){
        defer routine_exit(4)
        for {
            val:= <-s_2_2
            if val == nil {
                fmt.Println("channel closed.")
                return 
            }
            if vint, ok := val.(int); ok {
                fmt.Println("sub2 chan, value = ", vint)
            }
        }
    }()

    time.Sleep(2 * time.Second)
    fmt.Println("Notify eventtype 1...")
    la_event.Notify(1,1)
    fmt.Println("Notify eventtype 2...")
    la_event.Notify(2,2)


    fmt.Println("Unscribe s_1_2 ...")
    la_event.UnSubscribe(1,s_1_2)

    fmt.Println("NotifyAll...")
    la_event.NotifyAll(5)
    fmt.Println("Unscribe all...")
    la_event.UnSubscribe(1,s_1_1)
    la_event.UnSubscribe(1,s_1_2)
    la_event.UnSubscribe(2,s_2_1)
    la_event.UnSubscribe(2,s_2_2)
    time.Sleep(1 * time.Second)
    fmt.Println("NotifyAll after unscribe all...")
    la_event.NotifyAll(6)
}
