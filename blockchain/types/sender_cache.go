// Copyright 2020 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2014 The go-ethereum Authors.
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

package types

import (
	"errors"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hpb-project/go-hpb/common"
)

var (
	errNotFind  = errors.New("key not found")
	cacheLength = 400000
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
		v, find := this.cache.Get(txhash)
		if find {
			return v.(common.Address), nil
		}
	}
	return common.Address{}, errNotFind
}

func (this *SenderCache) GetOrSet(txhash common.Hash, addr common.Address) {
	if this.cache != nil {
		_, find := this.cache.Get(txhash)
		if !find {
			this.cache.Add(txhash, addr)
		}
	}
}

func (this *SenderCache) Delete(txhash common.Hash) {
	if this.cache != nil {
		this.cache.Remove(txhash)
	}
}
