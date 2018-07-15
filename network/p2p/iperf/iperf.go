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

	C.iperf_server_init(C.int(port))

	if ret := C.iperf_server_start();ret != 0{
		log.Error("iperf server stop error.")
		return errServer
	}

	return nil

}

func KillSever()  {

	C.iperf_server_kill()
	return
}

func StartTest(host string, port int, duration int) (string) {
	result := C.GoString(C.iperf_test(C.CString(host),C.int(port),C.int(duration)))

	/*
	var dat map[string]interface{}
	json.Unmarshal([]byte(result), &dat)


	for _, item := range dat {

		log.Info("result","item",item)

		//end := v.([]interface{})
		//for _, wsItem := range end {
		//	wsMap := wsItem.(map[string]interface{})
		//	if vCw, ok := wsMap["sum_sent"]; ok {
		//		cw := vCw.([]interface{})
		//		for _, cwItem := range cw {
		//			cwItemMap := cwItem.(map[string]interface{})
		//			if w, ok := cwItemMap["bits_per_second"]; ok {
		//				sendRate := w.(string)
		//				log.Info("sendRate","sendRate",sendRate)
		//			}
		//		}
		//	}
		//}
	}
	*/

	//log.Info("StartTest","result",result)
	return  result
}

