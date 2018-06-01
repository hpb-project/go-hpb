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
    m   sync.Mutex
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
    ErrInvalidParams         = errors.New("invalid params")
    ErrInitFailed            = errors.New("init failed")
    ErrReleaseFailed         = errors.New("release failed")
    ErrSignCheckFailed       = errors.New("sign check failed")
    ErrHWSignFailed          = errors.New("hw sign failed")
    ErrUnknownEvent          = errors.New("unknown event")
    ErrIDNotMatch            = errors.New("id not match")
    ErrUpdateFailed          = errors.New("update failed")
    ErrUpdateAbortFailed     = errors.New("update abort failed")

    boeRecoverPubTps         = int32(0)
    bcontinue                = false
    boeHandle                = &BoeHandle{boeEvent:routinue.NewEvent(), boeInit:false}
)


func BoeGetInstance() (*BoeHandle) {
    return boeHandle
}

func localInfoId() uint32 {
    // scan local local info and calc the id.
    return 0xfffffff
}

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

func (boe *BoeHandle) Init()(error) {
    boe.m.Lock()
    defer boe.m.Unlock()

    if boe.boeInit {
        return nil
    }
    ret := C.BOEInit()
    if ret == C.BOE_OK {
        // calc local id, then set it to board, if id is not matched, 
        // the board will not work correctly.
        id := localInfoId()
        ret = C.SetBOEID(C.uint(id))
        if ret != C.BOE_OK {
            return ErrIDNotMatch
        }
        boe.boeInit = true
        bcontinue = true
        go innerResetCounter()
        return nil
    }
    return ErrInitFailed

}

func (boe *BoeHandle) Release() (error) {
    boe.m.Lock()
    defer boe.m.Unlock()

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
    var ret = C.BOEFWUpdate()
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

func (boe *BoeHandle) ValidateSign(hash []byte, r []byte, s []byte, v byte) ([]byte, error) {
    boe.m.Lock()
    defer boe.m.Unlock()

    if len(hash) != 32 || len(r) != 32 || len(s) != 32 {
        return nil,ErrInvalidParams
    }
    atomic.AddInt32(&boeRecoverPubTps, 1)
    var result = make([]byte, 64)

    if(boeRecoverPubTps > 100) {
        // use hardware
        var (
            c_hash = (*C.uchar)(unsafe.Pointer(&hash[0]))
            c_r = (*C.uchar)(unsafe.Pointer(&r[0]))
            c_s = (*C.uchar)(unsafe.Pointer(&s[0]))
            c_v = C.uchar(v)
        )

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

