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
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L . -lboe
#include "boe.h"
*/
import "C"
import (
    "unsafe"
    "sync/atomic"
    "time"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/common/crypto"
)

type BoeHandle struct {
    boeEvent *event.SyncEvent
    boeInit  bool
}

type SignResult struct {
    r   []byte 
    s   []byte 
    v   byte 
}

type TVersion struct {
    ver   uint8 
}

type BoeId uint32


const (
    BoeEventBase event.EventType = iota+100
    BoeEventMax
)

var (
    boeRecoverPubTps         = int32(0)
    bcontinue                = false
    boeHandle                = &BoeHandle{boeEvent:event.NewEvent(), boeInit:false}
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

    ret := C.boe_init()
    if ret == C.BOE_OK {
        boe.boeInit = true
        bcontinue = true
        go innerResetCounter()
        return nil
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return ErrInitFailed
}

func (boe *BoeHandle) Release() (error) {

    bcontinue = false
    ret := C.boe_release()
    if ret == C.BOE_OK {
        return nil
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return ErrInitFailed
}

func (boe *BoeHandle) SubscribeEvent(event event.EventType) (event.Subscriber,error) {
    if (event < BoeEventMax) && (event > BoeEventBase) {
        sub := boe.boeEvent.Subscribe(event)
        return sub, nil
    }
    return nil,ErrUnknownEvent
}

func (boe *BoeHandle) GetBindAccount()([]byte, error){
    var acc = make([]byte, 256)
    ret := C.boe_get_bind_account((*C.uchar)(unsafe.Pointer(&acc[0])))
    if ret == C.BOE_OK{
        return acc,nil
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return nil,ErrGetAccountFailed

}

func (boe *BoeHandle) SetBindAccount(account []byte) (error){

    ret := C.boe_set_bind_account((*C.uchar)(unsafe.Pointer(&account[0])))
    if ret == C.BOE_OK{
        return nil
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return ErrGetAccountFailed
}

func (boe *BoeHandle) GetHWVersion() TVersion {
    var v TVersion
    ret := C.boe_get_hw_version((*C.TVersion)(unsafe.Pointer(&v)))
    if ret == C.BOE_OK {
        return v
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return v
}

func (boe *BoeHandle) GetFWVersion() TVersion {
    var v TVersion
    ret := C.boe_get_fw_version((*C.TVersion)(unsafe.Pointer(&v)))
    if ret == C.BOE_OK {
        return v
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return v
}

func (boe *BoeHandle) GetAXUVersion() TVersion {
    var v TVersion
    ret := C.boe_get_axu_version((*C.TVersion)(unsafe.Pointer(&v)))
    if ret == C.BOE_OK {
        return v
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return v
}

func (boe *BoeHandle) GetRandom() uint32{
    var r uint32
    C.boe_get_random((*C.uint)(unsafe.Pointer(&r)))
    return r
}

func (boe *BoeHandle) GetBoeId() BoeId{
    var id BoeId
    ret := C.boe_get_boeid((*C.uint)(unsafe.Pointer(&id)))
    if ret != C.BOE_OK{
        log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
        C.boe_err_free(ret)
    }
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
    var ret = C.boe_upgrade((*C.uchar)(unsafe.Pointer(&image[0])), (C.int)(len))
    if ret == C.BOE_OK {
        return nil
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return ErrUpdateFailed
}

func (boe *BoeHandle) FWUpdateAbort() error{
    var ret = C.boe_upgrade_abort()
    if ret == C.BOE_OK {
        return nil
    }
    log.Error("ecode:",uint32(ret.ecode),",emsg:", ret.emsg)
    C.boe_err_free(ret)
    return ErrUpdateAbortFailed
}

func (boe *BoeHandle) ValidateSign(hash []byte, r []byte, s []byte, v byte) ([]byte, error) {

    atomic.AddInt32(&boeRecoverPubTps, 1)
    var result = make([]byte, 64)

    if(boeRecoverPubTps > 100) {
        // use hardware
        var (
            m_sig  = make([]byte, 97)
            c_sig = (*C.uchar)(unsafe.Pointer(&m_sig[0]))
        )
        copy(m_sig[32-len(hash):32], hash)
        copy(m_sig[64-len(r):64], r)
        copy(m_sig[96-len(s):96], s)
        m_sig[96] = v

        c_ret := C.boe_valid_sign(c_sig, (*C.uchar)(unsafe.Pointer(&result[0])))
        if c_ret != C.BOE_OK {
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
    var result = make([]byte, 65)
    var sig = &SignResult{r: make([]byte, 32), s: make([]byte, 32)}
    var ret = C.boe_hw_sign((*C.char)(unsafe.Pointer(&data[0])), (*C.uchar)(unsafe.Pointer(&result[0])))
    if ret == C.BOE_OK {
        copy(sig.r, result[0:32])
        copy(sig.s, result[32:64])
        sig.v = result[64]
        return sig, nil

    } 
    return nil, ErrHWSignFailed
}

func (boe *BoeHandle) GetNextHash(hash []byte) ([]byte, error) {
    var result = make([]byte, 256)
    var ret = C.boe_get_s_random((*C.uchar)(unsafe.Pointer(&hash[0])), (*C.uchar)(unsafe.Pointer(&result[0])))
    if ret == C.BOE_OK {
        return result, nil

    } 
    return nil, ErrGetNextHashFailed
}

func (boe *BoeHandle) Hash(data []byte) ([] byte, error) {
    var hash = make([]byte, 32)
    return hash, nil
}
