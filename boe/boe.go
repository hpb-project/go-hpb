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

/*
#cgo CFLAGS: -I./core
#include "core/boe.h"
#include "core/boe.c"
#include "core/common.c"
#include "core/community.c"
#include "core/tsu_connector.c"
#include "core/axu_connector.c"
*/
import "C"
import (
    "unsafe"
    "errors"
    "sync"
    "sync/atomic"
    "time"

    "github.com/hpb-project/go-hpb/routinue"
    "github.com/hpb-project/go-hpb/common/crypto"
)

type BoeHandle struct {
    boeEvent *routinue.Event
    boeInit  bool
}

type SignResult struct {
    val   []byte 
}

type TVersion struct {
    ver   uint8 
}

type BoeId uint32


const (
    BoeEventBase routinue.EventType = iota+100
    BoeEventMax
)

var (
    boeRecoverPubTps         = int32(0)
    bcontinue                = false
    boeHandle                = &BoeHandle{boeEvent:routinue.NewEvent(), boeInit:false}
)

func innerResetCounter() {
    timestamp1 := time.Now().UTC().UnixNano()
    var zero int32 = 0
    for ;bcontinue==true; {
        timestamp2 := time.Now().UTC().UnixNano()
        if(500 <= (timestamp2 - timestamp1)/1000/1000) {
            boeRecoverPubTps = atomic.LoadInt32(&zero)
            timestamp1 = timestamp2
        }
    }
}

func BoeGetInstance() (*BoeHandle) {
    return boeHandle
}

func (boe *BoeHandle) Init()(error) {
    if boe.boeInit {
        return nil
    }

    ret := C.BOEInit()
    if ret == C.BOE_OK {
        boe.boeInit = true
        bcontinue = true
        go innerResetCounter()
        return nil
    }
    return ErrInitFailed
}

func (boe *BoeHandle) Release() (error) {

    bcontinue = false
    ret := C.BOERelease()
    if ret == C.BOE_OK {
        return nil
    }
    return ErrInitFailed
}

func (boe *BoeHandle) SubscribeEvent(event routinue.EventType) (routinue.Subscriber,error) {
    if (event < BoeEventMax) && (event > BoeEventBase) {
        sub := boe.boeEvent.Subscribe(event)
        return sub, nil
    }
    return nil,ErrUnknownEvent
}

func (boe *BoeHandle) HWBind(account []byte) (error){
    // 1. calc local id.
    var id = localInfoId()
    // 2. call c interface, and check result.
    //C.BOEHWBind(id, account)
    return nil
}

func (boe *BoeHandle) GetHWVersion() TVersion {
    var v TVersion
    v.ver = uint8(C.GetBOEHWVersion())
    return v
}

func (boe *BoeHandle) GetFWVersion() TVersion {
    var v TVersion
    v.ver = uint8(C.GetBOEFWVersion())
    return v
}

func (boe *BoeHandle) GetAXUVersion() TVersion {
    var v TVersion
    v.ver = uint8(C.GetBOEAXUVersion())
    return v
}

func (boe *BoeHandle) GetRandom() uint32{
    var r = uint32(C.GetRand())
    return r
}

func (boe *BoeHandle) GetBoeId() BoeId{
    var id = BoeId(C.GetBOEID())
    return id
}

func (boe *BoeHandle) FWUpdate() error{
    // download version record file.
    // get board version info.
    // get correct update image url.
    // download update image.
    // call C api to update.
    var image = make([]byte, 1024*10*1024)
    var len = 10*1024*1024;
    var ret = C.BOEFWUpdate(image, len)
    if ret == C.BOE_OK {
        return nil
    }
    return ErrUpdateFailed
}

func (boe *BoeHandle) FWUpdateAbort() error{
    var ret = C.BOEFWUpdateAbort()
    if ret == C.BOE_OK {
        return nil
    }
    return ErrUpdateFailed
}

func (boe *BoeHandle) SetBoundAccount(baccount []byte) (error) {
    // call C interface.
    ret := C.BOE_OK//C.BOESetBindInfo((*C.uchar)((unsafe.Pointer)(&bid[0])), (*C.uchar)((unsafe.Pointer)(&baccount[0])))
    if ret == C.BOE_OK {
        return baccount, nil
    }
    return ErrHWSignFailed
}

func (boe *BoeHandle) GetBoundAccount() ([]byte, error) {
    var (
        baccount = make([]byte, 32)
    )
    // call C interface.
    ret := C.BOE_OK//C.BOEGetBindInfo((*C.uchar)((unsafe.Pointer)(&bid[0])), (*C.uchar)((unsafe.Pointer)(&baccount[0])))
    if ret == C.BOE_OK {
        return baccount, nil
    }
    return nil,ErrHWSignFailed
}

func (boe *BoeHandle) ValidateSign(hash []byte, r []byte, s []byte, v byte) ([]byte, error) {

    atomic.AddInt32(&boeRecoverPubTps, 1)
    var result = make([]byte, 64)

    if(boeRecoverPubTps > 100) {
        // use hardware
        var (
            m_hash = make([] byte, 32)
            m_r = make([] byte, 32)
            m_s = make([] byte, 32)

            c_hash = (*C.uchar)(unsafe.Pointer(&m_hash[0]))
            c_r = (*C.uchar)(unsafe.Pointer(&m_r[0]))
            c_s = (*C.uchar)(unsafe.Pointer(&m_s[0]))
            c_v = C.uchar(v)
        )
        copy(m_hash[32-len(hash):32], hash)
        copy(m_r[32-len(s):32], r)
        copy(m_s[32-len(s):32], s)

        c_ret := C.BOEValidSign(c_hash, c_r, c_s, c_v, (*C.uchar)(unsafe.Pointer(&result[0])))
        if c_ret != 0 {
            return nil,ErrSignCheckFailed
        }
    }else {
        // use software
        var (
            sig = make([]byte, 65)
        )
        copy(sig[32-len(r):32], r)
        copy(sig[64-len(s):64], s)
        sig[64] = v
        pub, err := crypto.Ecrecover(hash[:], sig)
        if(err != nil) {
            return nil, ErrSignCheckFailed
        }
        copy(result[:], pub[1:])
    }


    return result, nil
}

func (boe *BoeHandle) HWSign(data []byte) (*SignResult, error) {
    var result = &SignResult{val: make([]byte, 32)}
    var ret = C.BOEHWSign((*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)), (*C.uchar)(unsafe.Pointer(&result.val[0])))
    if ret != 0 {
        return nil, ErrHWSignFailed
    } 
    return result, nil
}
