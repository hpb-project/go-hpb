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

type Iperf struct {
	SrvPort  uint

	CliHost  string
	CliPort  uint
}

func (iperf *Iperf) StartSever() (error) {
	C.iperf_server(C.int(5201))
	return nil

}


func (iperf *Iperf) StartTest() (error) {
	C.iperf_test(C.CString("127.0.0.1"),C.int(5201))
	return  nil
}

