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
#include <stdio.h>
int upgrade_call_back_cgo(int progress, char *msg)
{
    static int lp = 0;
    
    if(progress >= 0 && progress <= 100)
    {
        if(lp != progress)
        {
            printf("Upgrade %d%%, msg:%s\r\n", progress, msg);
        }
        lp = progress;
    }
    return 0;
}

*/
import "C"
import (
    "unsafe"
    "fmt"
    "sync/atomic"
	"github.com/hpb-project/go-hpb/common/log"
	//"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/common/crypto"
)

type BoeHandle struct {
   // boeEvent *event.SyncEvent
    boeInit  bool
}


type TVersion struct {
    H int
    M int
    F int 
    D int
}

/*const (
   // BoeEventBase event.EventType = iota+100
    BoeEventMax
)*/

var (
    boeRecoverPubTps         = int32(0)
    bcontinue                = false
    boeHandle                = &BoeHandle{ boeInit:false}
)

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
        return nil
    }
    //fmt.Printf("Init ecode:%d, emsg:%s\r\n", uint32(ret.ecode), ret.emsg)
    C.boe_err_free(ret)
    return ErrInitFailed
}

func (boe *BoeHandle) Release() (error) {

    bcontinue = false
    ret := C.boe_release()
    if ret == C.BOE_OK {
        return nil
    }
    fmt.Printf("Release ecode:%d, emsg:%s\r\n", uint32(ret.ecode), ret.emsg)
    C.boe_err_free(ret)
    return ErrInitFailed
}

/*func (boe *BoeHandle) SubscribeEvent(event event.EventType) (event.Subscriber,error) {
    if (event < BoeEventMax) && (event > BoeEventBase) {
        sub := boe.boeEvent.Subscribe(event)
        return sub, nil
    }
    return nil,ErrUnknownEvent
}*/


func (boe *BoeHandle) GetBindAccount()(string, error){
    var acc = make([]byte, 42)
    ret := C.boe_get_bind_account((*C.uchar)(unsafe.Pointer(&acc[0])))
    if ret == C.BOE_OK{
        var str string = string(acc[:])
        return str,nil
    }
    fmt.Printf("GetBindAccount ecode:%d, emsg:%s\r\n", uint32(ret.ecode), ret.emsg)
    C.boe_err_free(ret)
    return "",ErrGetAccountFailed

}

func (boe *BoeHandle) GetVersion() (TVersion,error) {
    var H,M,F,D C.uchar
    ret := C.boe_get_version(&H, &M, &F, &D)
    if ret == C.BOE_OK {
        var v TVersion = TVersion{H:int(H), M:int(M), F:int(F), D:int(D)}
        return v,nil
    }
    //fmt.Printf("GetVersion ecode:%d, emsg:%s\r\n", uint32(ret.ecode), ret.emsg)
    C.boe_err_free(ret)
    var v TVersion
    return v,ErrInitFailed
}


func (boe *BoeHandle) GetRandom() ([]byte){
    var ran = make([]byte, 32)
    C.boe_get_random((*C.uchar)(unsafe.Pointer(&ran[0])))
    return ran
}

func (boe *BoeHandle) GetBoeId() (string,error){
    var sn string
    ret := C.boe_get_boesn((*C.uchar)(unsafe.Pointer(&sn)))
    if ret != C.BOE_OK{
        fmt.Printf("ecode:%d, emsg:%s\r\n", uint32(ret.ecode), ret.emsg)
        C.boe_err_free(ret)
        return "", ErrGetSNFailed
    }
    return sn,nil
}

func (boe *BoeHandle) FWUpdate() error{
    // download version record file.
    // get board version info.
    // get correct update image url.
    // download update image.
    // call C api to update.
    version,err := boe.GetVersion()
    if err != nil {
        fmt.Println("board connect failed, update abort.")
        return ErrUpdateFailed
    }
    image, err := downloadrelease(version.H, version.M, version.F, version.D)
    if err == ErrNoNeedUpdate {
        fmt.Println("You are using the newest firmware.")
        return nil
    }
    if err != nil {
        fmt.Println("download firmware failed.")
        return err
    }
    var len = len(image)
    fmt.Println("image len = %d", len)

    C.boe_reg_update_callback((C.BoeUpgradeCallback)(unsafe.Pointer(C.upgrade_call_back_cgo)))
    var ret = C.boe_upgrade((*C.uchar)(unsafe.Pointer(&image[0])), (C.int)(len))
    if ret == C.BOE_OK {
        fmt.Println("upgrade successed.")
        return nil
    }
    fmt.Printf("UpgradeAbort ecode:%d, emsg:%s\n",uint32(ret.ecode), ret.emsg)
    C.boe_err_free(ret)
    return ErrUpdateFailed
}

func (boe *BoeHandle) FWUpdateAbort() error{
    var ret = C.boe_upgrade_abort()
    if ret == C.BOE_OK {
        return nil
    }
    fmt.Printf("UpgradeAbort ecode:%d, emsg:%s\n",uint32(ret.ecode), ret.emsg)
    C.boe_err_free(ret)
    return ErrUpdateAbortFailed
}

func (boe *BoeHandle) HWCheck() bool {
    var ret = C.boe_hw_check()
    if ret == C.BOE_OK {
        log.Info("boe board is ok.")
        return true
    }else {
        log.Info("boe board not find.")
        return false
    }
}

func (boe *BoeHandle) HW_Auth_Sign(random []byte) ([]byte, error) {
    var signature = make([]byte, 64)
    if len(random) != 32 {
        return nil, ErrHWSignFailed
    }
    var ret = C.boe_hw_sign((*C.uchar)(unsafe.Pointer(&random[0])), (*C.uchar)(unsafe.Pointer(&signature[0])))
    if ret == C.BOE_OK {
        return signature, nil
    } 
    return nil, ErrHWSignFailed
}

func (boe *BoeHandle) HW_Auth_Verify(random []byte, hid []byte, cid[]byte, signature []byte) bool {
    if len(random) != 32 || len(hid) != 32 || len(cid) != 64 || len(signature) != 64 {
        return false
    }
    var ret = C.boe_p256_verify((*C.uchar)(unsafe.Pointer(&random[0])), (*C.uchar)(unsafe.Pointer(&hid[0])),
(*C.uchar)(unsafe.Pointer(&cid[0])), (*C.uchar)(unsafe.Pointer(&signature[0])))
    if ret == C.BOE_OK {
        return true
    } 
    return false
}

func (boe *BoeHandle) ValidateSign(hash []byte, r []byte, s []byte, v byte) ([]byte, error) {

    atomic.AddInt32(&boeRecoverPubTps, 1)
    var result = make([]byte, 65)

    var (
        m_sig  = make([]byte, 97)
        c_sig = (*C.uchar)(unsafe.Pointer(&m_sig[0]))
    )
    copy(m_sig[32-len(r):32], r)
    copy(m_sig[64-len(s):64], s)
    copy(m_sig[96-len(hash):96], hash)
    m_sig[96] = v

    c_ret := C.boe_valid_sign(c_sig, (*C.uchar)(unsafe.Pointer(&result[1])))
    //loushl change to debug
    if false && c_ret == C.BOE_OK {
    	log.Trace("boe validate sign success")
        result[0] = 4
        return result,nil
    }

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

    copy(result[:], pub[0:])
    log.Trace("software validate sign success")

    return result, nil
}


func (boe *BoeHandle) GetNextHash(hash []byte) ([]byte, error) {
    var result = make([]byte, 32)
    if len(hash) != 32 {
        return nil, ErrGetNextHashFailed
    }
    var ret = C.boe_get_s_random((*C.uchar)(unsafe.Pointer(&hash[0])), (*C.uchar)(unsafe.Pointer(&result[0])))
    if ret == C.BOE_OK {
        return result, nil
    } 
    return nil, ErrGetNextHashFailed
}
