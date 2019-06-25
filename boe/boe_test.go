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

package boe
import (
    "fmt"
    "testing"
)
var (
    boe = BoeGetInstance()

)

func TestCheck(t *testing.T) {
    err := boe.Init()
    if err != nil {
        log.Error("boe init failed")
    }
    boe.HWCheck()
}

func TestUpgrade(t *testing.T) {
    err := boe.FWUpdate()
    if err != nil {
        log.Error("boe upgrade failed")
    }
    log.Debug("boe upgrade successful.")
}

func TestValidateSign(t *testing.T) {
    var (
        hash = make([]byte, 32)
        r    = make([]byte, 32)
        s    = make([]byte, 32)
    )
    var v byte

    result,err := boe.ValidateSign(hash, r, s, v)
    if err == nil {
        //fmt.Printf("len(x)=%d\n", len(x))
        for i:=0; i < len(result); i++ {
            fmt.Printf("result[%d]=%02x\n", i, result[i])
        }
    }else {
        fmt.Printf("check failed\n")
    }

}

func TestHWSign(t *testing.T) {
    var (
        hash = "test"
    )

    result,err := boe.HWSign([]byte(hash))
    if err == nil {
        //fmt.Printf("len(x)=%d\n", len(x))
        for i:=0; i < 32; i++ {
            fmt.Printf("signval[%d]=%02x\n",i,result.r[i])
        }
    }
}

func TestNewEvent(t *testing.T) {
    var ver = boe.GetHWVersion()
    fmt.Printf("hwversion = %02x\n", ver)
}
