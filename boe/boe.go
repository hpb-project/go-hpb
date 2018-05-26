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

package BOE

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
)

type SignResult struct {
    r   []byte 
    s   []byte 
    v   byte
}

var (
    ErrInvalidParams         = errors.New("invalid params")
    ErrSignCheckFailed       = errors.New("sign check failed")
    ErrHWSignFailed       = errors.New("hw sign failed")
)

func BOEGetHWVersion() int {
    var ver = int(C.GetBOEHWVersion())
    return ver
}

func BOEValidateSign(hash []byte, r []byte, s []byte, v byte) ([]byte, []byte, error) {
    if len(hash) != 32 || len(r) != 32 || len(s) != 32 {
        return nil,nil,ErrInvalidParams
    }

    var (
        x = make([]byte, 32)
        y = make([]byte, 32)
        c_hash = (*C.uchar)(unsafe.Pointer(&hash[0]))
        c_r = (*C.uchar)(unsafe.Pointer(&r[0]))
        c_s = (*C.uchar)(unsafe.Pointer(&s[0]))
        c_v = C.uchar(v)
    )
    var c_result *C.PublicKey_t
    c_result = C.new_pubkey()
    defer C.delete_pubkey(c_result)
    c_result.x = (*C.uchar)(unsafe.Pointer(&x[0]))
    c_result.y = (*C.uchar)(unsafe.Pointer(&y[0]))
    
    c_ret := C.BOEValidSign(c_hash, c_r, c_s, c_v, c_result)
    if c_ret != 0 {
        return nil,nil,ErrSignCheckFailed
    }
    return x, y, nil
}

func BOEHWSign(data []byte) (*SignResult, error) {
    var result = &SignResult{r: make([]byte, 32), s:make([]byte,32)}
    var c_sign_result *C.SignResult_t 
    c_sign_result = C.new_signresult()
    defer C.delete_signresult(c_sign_result)
    c_sign_result.r = (*C.uchar)(unsafe.Pointer(&result.r[0]))
    c_sign_result.s = (*C.uchar)(unsafe.Pointer(&result.s[0]))
    c_sign_result.v = (*C.uchar)(&result.v)
    var ret = C.BOEHWSign((*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)), c_sign_result)
    if ret != 0 {
        return nil, ErrHWSignFailed
    } 

    return result, nil
}
