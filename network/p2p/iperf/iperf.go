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
#cgo CFLAGS: -I./iperf35
#cgo LDFLAGS: -L./iperf35/lib/ -l iperf
#include "iperf35/iperf.h"
#include "iperf35/iperf.c"
*/
import "C"
import (
	"github.com/hpb-project/go-hpb/common/log"
	"errors"
	"time"
	"encoding/json"
	"strings"
)

var (
	errServer          = errors.New("iperf server error")
	errServerTimeout   = errors.New("iperf server stop time out")
)

type Iperf struct {
	SrvPort  int
	quit     chan int

	CliHost  string
	CliPort  int
}

func (iperf *Iperf) StartSever(port int) error {
	iperf.SrvPort = port

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

func (iperf *Iperf) StartTest(host string, port int, duration int) (error) {
	result := C.GoString(C.iperf_test(C.CString(host),C.int(port),C.int(duration)))

	log.Info("StartTest","result",result)
	return  nil
}
///////////////////////////////////////////////////////////////////////////


func StartSever(port int) error {
	//TODO all is running

	C.iperf_server_init(C.int(port))
	if ret := C.iperf_server_start();ret != 0{
		log.Error("Iperf server stop error.")
		return errServer
	}

	return nil
}

func PauseSever() error {
	return  nil
}

func StopSever() error {
	return  nil
}

func KillSever()  {
	C.iperf_server_kill()
	return
}

func StartTest(host string, port int, duration int) (float64) {
	result := C.GoString(C.iperf_test(C.CString(host),C.int(port),C.int(duration)))

	//log.Info("test string","result",result)
	if !strings.Contains(result, "bits_per_second"){
		log.Warn("Test string in not right.")
		return 0
	}

	var dat map[string]interface{}
	json.Unmarshal([]byte(result), &dat)

	sum:= dat["end"].(map[string]interface{})

	sum_sent     := sum["sum_sent"].(map[string]interface{})
	sum_received := sum["sum_received"].(map[string]interface{})

	send := sum_sent["bits_per_second"].(float64)
	recv := sum_received["bits_per_second"].(float64)
	log.Debug("iperf test result","sendrate",send, "recvrate",recv,"avg",(send+recv)/2)
	return  (send+recv)/2
}

