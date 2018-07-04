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
	iperf = &Iperf{SrvPort:5201,CliHost:"127.0.0.1",CliPort:5201,quit: make(chan int)}
)

func TestValidateSign(t *testing.T) {

	time.Sleep(time.Second)
	iperf.StartTest("127.0.0.1",5202,5)
	//t.Log("iperf test","result",result)
}

//func TestValidateSign(t *testing.T) {
//
//	go iperf.StartSever(5202)
//
//	time.Sleep(time.Second*20)
//
//
//	err :=iperf.StopSever(3)
//
//	t.Log("Stop iperf server","err",err)
//
//}
