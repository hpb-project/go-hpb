package types

import (
	"errors"
	"github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/common"
)
var (
	errNotFind              = errors.New("key not found")
	cacheLength             = 400000
)

type SenderCache struct {
	cache *lru.Cache
}

var (
	Sendercache = &SenderCache{}
)

func init() {
	cache, _ := lru.New(cacheLength)
	Sendercache.cache = cache
}

func (this *SenderCache) Set(txhash common.Hash, addr common.Address) error {
	if this.cache != nil {
		this.cache.Add(txhash, addr)
	}
	return nil
}

func (this *SenderCache) Get(txhash common.Hash) (common.Address, error) {
	if this.cache != nil {
		v,find := this.cache.Get(txhash)
		if find {
			return v.(common.Address), nil
		}
	}
	return common.Address{}, errNotFind
}

func (this *SenderCache) GetOrSet(txhash common.Hash, addr common.Address) {
	if this.cache != nil {
		_,find := this.cache.Get(txhash)
		if !find {
			this.cache.Add(txhash, addr)
		}
	}
}
