package main

import (
	"bytes"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"log"

	"github.com/hpb-project/go-hpb/boe"
)

var (
	expectPubkey sync.Map
	received     int32
	errcount     int32
)

func boecallback(rs boe.RecoverPubkey, err error) {
	received += 1
	if err != nil {
		// log.Println("boecallback boe validatesign error")
		errcount += 1
		return
	}
	if len(rs.Pub) == 0 || rs.Pub[0] != 4 {
		// log.Println("boecallback boe invalid public key")
		errcount += 1
		return
	}
	if exp, exist := expectPubkey.Load(hex.EncodeToString(rs.TxHash)); !exist {
		log.Println("not found expect pubkey in callback")
	} else {
		pub := exp.([]byte)
		if bytes.Compare(pub, rs.Pub) != 0 {
			log.Println("compare pubkey failed", "got ", hex.EncodeToString(rs.Pub), "expect", hex.EncodeToString(pub))
			errcount += 1
		}
	}
}

func boestress(groups []*Group, b *boe.BoeHandle) {
	var total int32

	wg := sync.WaitGroup{}
	start := time.Now()
	for i := 0; i < *routines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			loops := *pTotal / (*routines)
			for m := 0; m < loops; m++ {
				t := m*(*routines) + idx
				if t > *pTotal {
					break
				}
				atomic.AddInt32(&total, 1)

				hash := groups[t].msg
				r := groups[t].sig[:32]
				s := groups[t].sig[32:64]
				v := groups[t].sig[64]
				e := b.ASyncValidateSign(groups[t].msg, hash, r, s, v)
				if e != nil {
					log.Println("send to async recover pubkey failed")
				}
			}
		}(i)
	}

	s := time.Now()
	for {

		if received == total && total > 0 {
			break
		} else {
			e := time.Now()
			if e.Sub(s).Milliseconds() > 500 {
				log.Println("wait received", "got ", received, "expect ", total)
				s = time.Now()
			}

			time.Sleep(time.Millisecond * 2)
		}
	}
	wg.Wait()
	end := time.Now()
	d := end.Sub(start).Milliseconds()
	log.Printf("test count %d and cost %dms, received %d, error %d\n", total, d, received, errcount)
}

func prepareBoeTest(groups []*Group) *boe.BoeHandle {
	b := boe.BoeGetInstance()
	b.Init()
	b.RegisterRecoverPubCallback(boecallback)
	received = 0
	errcount = 0
	for _, g := range groups {
		expectPubkey.Store(hex.EncodeToString(g.msg), g.pubkey)
	}

	return b
}
