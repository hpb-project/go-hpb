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


/*
#cgo CFLAGS: -I./iperf
#cgo LDFLAGS: ./iperf/lib/libiperf.a
#include "iperf/iperf.h"
#include "iperf/iperf.c"
*/
import "C"
import (
	"github.com/hpb-project/go-hpb/common/log"
	//"time"
	"errors"
	"time"
)
var (
	errServerTimeout   = errors.New("iperf server stop time out")
)
type Iperf struct {
	SrvPort  uint

	CliHost  string
	CliPort  uint
	quit     chan int
}

func (iperf *Iperf) StartSever(port int) error {

	C.iperf_server_init(C.int(port))

	ret := C.iperf_server_start()

	iperf.quit <- int(ret)

	return nil

}

func (iperf *Iperf) KillSever() error {

	C.iperf_server_kill()
	return nil
}

func (iperf *Iperf) StopSever(seconds uint) error {

	timeout  := time.NewTimer(0)
	timeout.Reset(time.Second)
	defer timeout.Stop()

	timeoutCount := uint(0)
loop:
	for {
		select {
		case ret := <-iperf.quit:
			log.Info("Stop server ok.","ret",ret)
			break loop
		case <-timeout.C:
			C.iperf_server_stop()
			timeoutCount =timeoutCount+1
			if timeoutCount > seconds {
				C.iperf_server_kill()
				log.Info("Stop server time out")
				return errServerTimeout
			}
			timeout.Reset(time.Second)
		}
	}


	return nil
}

func (iperf *Iperf) StartTest() (error) {
	C.iperf_test(C.CString("127.0.0.1"),C.int(5201))
	return  nil
}

