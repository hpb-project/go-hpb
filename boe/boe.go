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
#include "aq.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define RESULT_QUEUE_LEN (10000)
#define HASH_LEN (32)
#define SIG_LEN (97)
#define PUB_LEN (64)

typedef struct SResult{
    unsigned char *txhash;
    unsigned char *sig;
    unsigned char *pub;
    unsigned int  flag;
}SResult;

SResult *rsNew()
{
    SResult *ret = (SResult*)malloc(sizeof(SResult));
    ret->txhash = (unsigned char *)malloc(HASH_LEN);
    ret->sig = (unsigned char *)malloc(SIG_LEN);
    ret->pub = (unsigned char *)malloc(PUB_LEN+1);
    ret->flag = 0;
    return ret;
}

void rsFree(SResult *r)
{
    if(r)
    {
        if(r->pub)
            free(r->pub);
        if(r->sig)
            free(r->sig);
        if(r->txhash)
            free(r->txhash);
        free(r);
    }
}

static AtomicQ rQueue;
int initRQ()
{
    return aq_init(&rQueue, RESULT_QUEUE_LEN);
}

int pushResult(SResult *result)
{
    AQData* data = aqd_new(sizeof(unsigned char *));
    data->buf = (unsigned char*)result;
    return aq_push(&rQueue, data);
}

SResult* getResult()
{
    AQData* data = aq_pop(&rQueue);
    if(data != NULL)
    {
        SResult *ret = (SResult*)data->buf;
        data->buf = 0;
        aqd_free(data);
        return ret;
    }
    return NULL;
}

int qlen()
{
    return aq_len(&rQueue);
}

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

static void hex_dump(unsigned char * data, int len)
{
    printf("0x");
    for(int i = 0; i < len; i++)
        printf("%02x", data[i]);

    printf("\n");
}

int recover_pubkey_callback(unsigned char *pub, unsigned char *sig,void *param, int param_len)
{
    SResult *r = rsNew();
    if(sig)
    {
        //printf("%s: sig ", "recover_pubkey_callback");
        //hex_dump(sig, SIG_LEN);
        memcpy(r->sig, sig, SIG_LEN);
    }
    if(param)
    {
        memcpy(r->txhash, param, HASH_LEN);
    }

    if(pub)
    {
        //printf("%s: pub ", "recover_pubkey_callback");
        //hex_dump(pub, PUB_LEN);

        r->flag = 0; // ok
        memcpy(r->pub+1, pub, PUB_LEN);
        r->pub[0] = 4;
    }
    else
    {
        r->flag = 1; // timeout
    }
    pushResult(r);

    return 0;
}



*/
import "C"
import (
	"fmt"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/log"
	"runtime"
	"time"
	"unsafe"
)

type TVersion struct {
	H int
	M int
	F int
	D int
}

// result for recover pubkey
type RecoverPubkey struct {
	TxHash []byte
	Hash   []byte
	Sig    []byte
	Pub    []byte
}

type BoeRecoverPubKeyFunc func(RecoverPubkey, error)

type TaskTh struct {
	isFull bool
	queue  chan RecoverPubkey
}

type postParam struct {
	rs  RecoverPubkey
	err error
}

type BoeHandle struct {
	boeInit   bool
	bcontinue bool
	rpFunc    BoeRecoverPubKeyFunc
	maxThNum  int
	thPool    []*TaskTh
	postCh    chan postParam
	idx       int
}

var (
	boeHandle  = &BoeHandle{boeInit: false, rpFunc: nil, maxThNum: 2}
	soft_cnt   uint32
	hard_cnt   uint32
	async_call uint32
	sync_call  uint32
)

func BoeGetInstance() *BoeHandle {
	return boeHandle
}

func cArrayToGoArray(ca unsafe.Pointer, goArray []byte, size int) {
	p := uintptr(ca)
	for i := 0; i < size; i++ {
		j := *(*byte)(unsafe.Pointer(p))
		goArray[i] = j
		p += unsafe.Sizeof(j)
		//fmt.Printf("cg[%d]=%02x, ca[%d]=%02x\n", i, goArray[i], i, j)
	}
}

func (t TVersion) VersionString() string {
	var v = fmt.Sprintf("%d.%d.%d.%d", t.H, t.M, t.F, t.D)
	return v
}

func PostRecoverPubkey(boe *BoeHandle) {
	var r *C.SResult
	for {
		if !boe.bcontinue {
			break
		}
		var err error
		r = C.getResult()
		if r == nil {
			time.Sleep(2 * time.Microsecond)
		} else {
			var fullsig = make([]byte, 97)
			rs := RecoverPubkey{TxHash: make([]byte, 32), Hash: make([]byte, 32), Sig: make([]byte, 65), Pub: make([]byte, 65)}

			cArrayToGoArray(unsafe.Pointer(r.txhash), rs.TxHash, len(rs.TxHash))
			cArrayToGoArray(unsafe.Pointer(r.sig), fullsig, len(fullsig))
			if r.flag == 0 {
				//log.Error("boe async callback recover pubkey success.")
				pubkey65 := make([]byte, 65)
				cArrayToGoArray(unsafe.Pointer(r.pub), pubkey65, len(pubkey65))
				copy(rs.Hash, fullsig[64:96])
				copy(rs.Sig[0:32], fullsig[0:32])
				copy(rs.Sig[32:64], fullsig[32:64])
				rs.Sig[64] = fullsig[96]
				hard_cnt++
				copy(rs.Pub, pubkey65)
				boe.postResult(&rs, err)
			} else {
				//log.Debug("boe async callback recover pubkey failed, and goto soft recover.")
				copy(rs.Hash, fullsig[64:96])
				copy(rs.Sig[0:32], fullsig[0:32])
				copy(rs.Sig[32:64], fullsig[32:64])
				rs.Sig[64] = fullsig[96]
				boe.postToSoft(&rs)
			}
		}
	}
}

func postCallback(boe *BoeHandle) {
	duration := time.Millisecond * 2
	timer := time.NewTimer(duration)
	defer timer.Stop()

	for {
		timer.Reset(duration)
		select {
		case <-timer.C:
			if !boe.bcontinue {
				return
			}
		case p, ok := <-boe.postCh:
			if !ok {
				return
			}
			if boe.rpFunc != nil {
				boe.rpFunc(p.rs, p.err)
			}
		}
	}
}

func (boe *BoeHandle) postResult(rs *RecoverPubkey, err error) {
	post := postParam{rs: *rs, err: err}
	select {
	case boe.postCh <- post:
		return
	default:
		log.Debug("boe postResult", "channel is full", len(boe.postCh))
	}
}

func (boe *BoeHandle) postToSoft(rs *RecoverPubkey) bool {

	for i := 0; i < boe.maxThNum; i++ {
		idx := (boe.idx + i) % boe.maxThNum
		select {
		case boe.thPool[idx].queue <- *rs:
			boe.idx++
			return true
		default:
			log.Debug("boe", "thPool ", idx, "is full", len(boe.thPool[idx].queue))
		}
	}
	return false
}

func (boe *BoeHandle) asyncSoftRecoverPubTask(queue chan RecoverPubkey) {
	duration := time.Millisecond * 2
	timer := time.NewTimer(duration)
	defer timer.Stop()

	for {
		timer.Reset(duration)
		select {
		case <-timer.C:
			if !boe.bcontinue {
				return
			}
		case rs, ok := <-queue:
			if !ok {
				return
			}
			pub, err := crypto.Ecrecover(rs.Hash, rs.Sig)
			if err == nil {
				copy(rs.Pub, pub)
			}
			soft_cnt++
			boe.postResult(&rs, err)
		}
	}
}

func (boe *BoeHandle) performance() {
	duration := time.Second * 1
	timer := time.NewTimer(duration)
	defer timer.Stop()

	soft_cnt = 0
	hard_cnt = 0
	for {
		timer.Reset(duration)
		select {
		case <-timer.C:
			if !boe.bcontinue {
				return
			}
			if soft_cnt > 0 || hard_cnt > 0 {
				log.Debug("boe performance", "hard_cnt", hard_cnt, "soft_cnt", soft_cnt, "async_call", async_call, "sync_call", sync_call)
			}
			soft_cnt = 0
			hard_cnt = 0
			async_call = 0
			sync_call = 0
		}
	}
}
func (boe *BoeHandle) Init() error {
	if boe.bcontinue {
		return nil
	}

	boe.bcontinue = true
	if runtime.NumCPU()/4 > boe.maxThNum {
		boe.maxThNum = runtime.NumCPU() / 4
	}

	boe.thPool = make([]*TaskTh, boe.maxThNum)
	boe.postCh = make(chan postParam, 1000000)

	for i := 0; i < boe.maxThNum; i++ {
		boe.thPool[i] = &TaskTh{isFull: false, queue: make(chan RecoverPubkey, 100000)}

		go boe.asyncSoftRecoverPubTask(boe.thPool[i].queue)
	}

	go postCallback(boe)
	go boe.performance()

	ret := C.boe_init()
	if ret == C.BOE_OK {
		boe.boeInit = true
		C.initRQ()
		go PostRecoverPubkey(boe)

		C.boe_valid_sign_callback((C.BoeValidSignCallback)(unsafe.Pointer(C.recover_pubkey_callback)))
		return nil
	}

	C.boe_err_free(ret)
	return ErrInitFailed
}

func (boe *BoeHandle) Release() error {

	boe.bcontinue = false
	ret := C.boe_release()
	if ret == C.BOE_OK {
		return nil
	}
	log.Error("boe", "Release ecode:", uint32(ret.ecode))
	C.boe_err_free(ret)
	return ErrInitFailed
}

func (boe *BoeHandle) RegisterRecoverPubCallback(call BoeRecoverPubKeyFunc) {
	boe.rpFunc = call
}

func (boe *BoeHandle) GetBindAccount() (string, error) {
	var acc = make([]byte, 42)
	ret := C.boe_get_bind_account((*C.uchar)(unsafe.Pointer(&acc[0])))
	if ret == C.BOE_OK {
		var str string = string(acc[:])
		return str, nil
	}
	log.Debug("boe", "GetBindAccount ecode", uint32(ret.ecode))
	C.boe_err_free(ret)
	return "", ErrGetAccountFailed

}

func (boe *BoeHandle) GetVersion() (TVersion, error) {
	var H, M, F, D C.uchar
	ret := C.boe_get_version(&H, &M, &F, &D)
	if ret == C.BOE_OK {
		var v TVersion = TVersion{H: int(H), M: int(M), F: int(F), D: int(D)}
		return v, nil
	}
	log.Debug("boe", "GetVersion ecode", uint32(ret.ecode))

	C.boe_err_free(ret)
	var v TVersion
	return v, ErrInitFailed
}

func (boe *BoeHandle) GetRandom() []byte {
	var ran = make([]byte, 32)
	C.boe_get_random((*C.uchar)(unsafe.Pointer(&ran[0])))
	return ran
}

func (boe *BoeHandle) GetBoeId() (string, error) {
	var sn string
	ret := C.boe_get_boesn((*C.uchar)(unsafe.Pointer(&sn)))
	if ret != C.BOE_OK {
		log.Debug("boe", "GetBoeId ecode", uint32(ret.ecode))

		C.boe_err_free(ret)
		return "", ErrGetSNFailed
	}
	return sn, nil
}

func (boe *BoeHandle) FWUpdate() error {
	// download version record file.
	// get board version info.
	// get correct update image url.
	// download update image.
	// call C api to update.
	version, err := boe.GetVersion()
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
	var ilen = len(image)
	fmt.Printf("image len = %d\n", ilen)

	C.boe_reg_update_callback((C.BoeUpgradeCallback)(unsafe.Pointer(C.upgrade_call_back_cgo)))
	var ret = C.boe_upgrade((*C.uchar)(unsafe.Pointer(&image[0])), (C.int)(ilen))
	if ret == C.BOE_OK {
		fmt.Println("upgrade successed.")
		return nil
	}
	fmt.Printf("[boe]UpgradeAbort ecode:%d\r\n", uint32(ret.ecode))
	C.boe_err_free(ret)
	return ErrUpdateFailed
}

func (boe *BoeHandle) FWUpdateAbort() error {
	var ret = C.boe_upgrade_abort()
	if ret == C.BOE_OK {
		return nil
	}
	fmt.Printf("[boe]UpgradeAbort ecode:%d\r\n", uint32(ret.ecode))
	C.boe_err_free(ret)
	return ErrUpdateAbortFailed
}

func (boe *BoeHandle) HWCheck() bool {
	var ret = C.boe_hw_check()
	if ret == C.BOE_OK {
		//log.Info("boe board is ok.")
		return true
	} else {
		//log.Info("boe board not find.")
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

func (boe *BoeHandle) HW_Auth_Verify(random []byte, hid []byte, cid []byte, signature []byte) bool {
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

func softRecoverPubkey(hash []byte, r []byte, s []byte, v byte) ([]byte, error) {
	var (
		result = make([]byte, 65)
		sig    = make([]byte, 65)
	)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = v
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		return nil, ErrSignCheckFailed
	}
	copy(result[:], pub[0:])
	return result, nil
}

func (boe *BoeHandle) ASyncValidateSign(txhash []byte, hash []byte, r []byte, s []byte, v byte) error {
	async_call = async_call + 1
	if (async_call >= 100) && (async_call%2 == 0) {
		rs := RecoverPubkey{TxHash: make([]byte, 32), Hash: make([]byte, 32), Sig: make([]byte, 65), Pub: make([]byte, 65)}
		copy(rs.TxHash, txhash)
		copy(rs.Hash, hash)
		copy(rs.Sig[32-len(r):32], r)
		copy(rs.Sig[64-len(s):64], s)
		rs.Sig[64] = v
		boe.postToSoft(&rs)

		return nil
	}

	var (
		m_sig   = make([]byte, 97)
		c_sig   = (*C.uchar)(unsafe.Pointer(&m_sig[0]))
		c_param = (*C.uchar)(unsafe.Pointer(&txhash[0]))
	)

	copy(m_sig[32-len(r):32], r)
	copy(m_sig[64-len(s):64], s)
	copy(m_sig[96-len(hash):96], hash)
	m_sig[96] = v

	c_ret := C.boe_valid_sign_recover_pub_async(c_sig, c_param, (C.int)(32))
	if c_ret == C.BOE_OK {
		return nil
	} else {
		rs := RecoverPubkey{TxHash: make([]byte, 32), Hash: make([]byte, 32), Sig: make([]byte, 65), Pub: make([]byte, 65)}
		copy(rs.TxHash, txhash)
		copy(rs.Hash, hash)
		copy(rs.Sig[32-len(r):32], r)
		copy(rs.Sig[64-len(s):64], s)
		rs.Sig[64] = v
		boe.postToSoft(&rs)

		return nil
	}
}

func (boe *BoeHandle) ValidateSign(hash []byte, r []byte, s []byte, v byte) ([]byte, error) {

	//var (
	//    result = make([]byte, 65)
	//    m_sig  = make([]byte, 97)
	//    c_sig = (*C.uchar)(unsafe.Pointer(&m_sig[0]))
	//)
	//sync_call = sync_call + 1
	//copy(m_sig[32-len(r):32], r)
	//copy(m_sig[64-len(s):64], s)
	//copy(m_sig[96-len(hash):96], hash)
	//m_sig[96] = v

	//c_ret := C.boe_valid_sign(c_sig, (*C.uchar)(unsafe.Pointer(&result[1])))
	//if c_ret == C.BOE_OK {
	//    result[0] = 4
	//    return result,nil
	//}

	return softRecoverPubkey(hash, r, s, v)
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

/*
 *  New Hash algorithm, supported by boe firmware v1.0.0.2
 */
func (boe *BoeHandle) GetNextHash_v2(hash []byte) ([]byte, error) {
	var result = make([]byte, 32)
	if len(hash) != 32 {
		return nil, ErrGetNextHashFailed
	}
	version, err := boe.GetVersion()
	if err != nil {
		return nil, ErrGetNextHashFailed
	}
	// The Hash_v2 is added at version v1.0.0.2.
	if version.F > 0 || version.D >= 2 {
		var ret = C.boe_get_n_random((*C.uchar)(unsafe.Pointer(&hash[0])), (*C.uchar)(unsafe.Pointer(&result[0])))
		if ret == C.BOE_OK {
			return result, nil
		}
	} else {
		log.Error("BOE firmware version is too low, not support Hash_v2.")
	}
	return nil, ErrGetNextHashFailed

}
