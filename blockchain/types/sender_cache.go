package types

import (
	"errors"
	"github.com/hpb-project/go-hpb/common"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errNotFind  = errors.New("key not found")
	cacheLength = 1000000
	cacheLru    = time.Duration(time.Microsecond * 60) // 1min
	forceFit    = int64(cacheLength * 90 / 100)        // 90% force fit
	forceLru    = time.Duration(time.Microsecond * 10)
)

type Citem struct {
	addr  common.Address
	stamp time.Duration
}

type SenderCache struct {
	cache sync.Map
	cnt   int64
	quit  chan interface{}
}

var (
	Sendercache = &SenderCache{quit: make(chan interface{})}
)

func init() {
	go Sendercache.KeepFit()
}

func (this *SenderCache) Set(txhash common.Hash, addr common.Address) error {
	this.cache.Store(txhash, &Citem{addr: addr, stamp: time.Duration(time.Now().Unix())})
	atomic.AddInt64(&this.cnt, 1)
	return nil
}

func (this *SenderCache) Get(txhash common.Hash) (common.Address, error) {
	if val, ok := this.cache.Load(txhash); ok {
		if addr, ok := val.(common.Address); ok {
			return addr, nil
		}
	}
	return common.Address{}, errNotFind
}

func (this *SenderCache) GetOrSet(txhash common.Hash, addr common.Address) {
	_, exist := this.cache.LoadOrStore(txhash, addr)
	if !exist {
		atomic.AddInt64(&this.cnt, 1)
	}
}

func (this *SenderCache) Quit() {
	this.quit <- new(interface{})
}

func (this *SenderCache) KeepFit() {
	duration := time.Second * 1
	timer := time.NewTimer(duration)
	defer timer.Stop()

	for {
		timer.Reset(duration)
		select {
		case <-this.quit:
			return
		case <-timer.C:
			this.cache.Range(func(k, v interface{}) bool {
				if item, ok := v.(Citem); ok {
					if item.stamp > cacheLru {
						this.cache.Delete(k)
						atomic.AddInt64(&this.cnt, -1)
					}
				}
				return true
			})

			for this.cnt >= forceFit {
				this.cache.Range(func(k, v interface{}) bool {
					if item, ok := v.(Citem); ok {
						if item.stamp > forceLru {
							this.cache.Delete(k)
							atomic.AddInt64(&this.cnt, -1)
						}
					}
					return true
				})
			}
		}

	}
}
