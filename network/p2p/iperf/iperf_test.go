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

package iperf

import (
	"testing"
	"time"

)

var (
	iperf = &Iperf{SrvPort:5201,CliHost:"127.0.0.1",CliPort:28201,quit: make(chan int)}
)

func TestValidateSign(t *testing.T) {

	var result = float64(0.0)
	ch := make(chan struct{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Log("iperf test result","result",r)
			}
		}()
		result = StartTest("127.0.0.1",28201,5)
		ch <- struct{}{}
	}()


	timeout := time.NewTimer(time.Second*15)
	defer timeout.Stop()

	select {
	case <-ch:
	case <-timeout.C:
	}
	t.Log("iperf test result","result",result)
	//var dat map[string]interface{}
	//json.Unmarshal([]byte(result), &dat)
	//
	////end := dat["end"]
	////t.Log("iperf test","end",end)
	//
	//sum:= dat["end"].(map[string]interface{})
	////t.Log("iperf test","sum_sent",sum["sum_sent"])
	////t.Log("iperf test","sum_received",sum["sum_received"])
	//
	//sum_sent     := sum["sum_sent"].(map[string]interface{})
	//sum_received := sum["sum_received"].(map[string]interface{})
	////t.Log("iperf test","sum_sent",sum_sent["bits_per_second"])
	////t.Log("iperf test","sum_received",sum_received["bits_per_second"])
	//
	//send := sum_sent["bits_per_second"].(float64)
	//t.Log("iperf test","sendrate",send)
	//
	//recv := sum_received["bits_per_second"].(float64)


}
