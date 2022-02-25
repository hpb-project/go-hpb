package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"log"

	"github.com/hpb-project/go-hpb/common/crypto"
)

var (
	input    = flag.String("f", "data.txt", "test data file path")
	pTotal   = flag.Int("total", 10000, "total tasks for stress test")
	routines = flag.Int("r", 1, "routine number and cpu cores to used")
	mode     = flag.Int("mode", 0, "0/1 (cpu/boe mode)")
)

func stressTest(groups []*Group) {
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
				pubk, _ := crypto.Ecrecover(groups[t].msg, groups[t].sig)
				if bytes.Compare(pubk, groups[t].pubkey) != 0 {
					log.Fatal("ecre recover failed", "got ", hex.EncodeToString(pubk), "expect ", hex.EncodeToString(groups[t].pubkey))
				}
				log.Println("got pubkey ", hex.EncodeToString(pubk), "expect", hex.EncodeToString(groups[t].pubkey))
			}
		}(i)
	}
	wg.Wait()
	end := time.Now()
	d := end.Sub(start).Milliseconds()
	log.Printf("test count %d and cost %dms\n", total, d)

}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(*routines)
	groups, err := loadData(*input, *pTotal)
	if err != nil {
		log.Fatal("load data failed", "err", err)
		return
	}
	if *mode == 0 {
		for i := 0; i < 10000; i++ {
			stressTest(groups)
		}
	} else if *mode == 1 {
		for i := 0; i < 10000; i++ {
			b := prepareBoeTest(groups)
			boestress(groups, b)
		}
	}

}
