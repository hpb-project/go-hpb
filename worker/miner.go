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

// Package miner implements Hpb block creation and mining.
package miner

import (
	"fmt"
	"sync/atomic"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/consensus"
	"github.com/hpb-project/ghpb/core"
	"github.com/hpb-project/ghpb/core/state"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/protocol/downloader"
	"github.com/hpb-project/ghpb/storage"
	"github.com/hpb-project/ghpb/core/event"
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/common/constant"
)

// Backend 接口
type Backend interface {
	AccountManager() *accounts.Manager
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
	ChainDb() hpbdb.Database
}

// Miner 结构体
type Miner struct {
	mux         *event.TypeMux
	worker      *worker
	coinbase    common.Address
	mining      int32
	hpb         Backend
	engine      consensus.Engine
	canStart    int32 // can start indicates whether we can start the mining operation
	shouldStart int32 // should start indicates whether we should start after sync
}

//构造函数
func New(hpb Backend, config *params.ChainConfig, mux *event.TypeMux, engine consensus.Engine) *Miner {
	miner := &Miner{
		hpb:      hpb,
		mux:      mux,
		engine:   engine,
		worker:   newWorker(config, engine, common.Address{}, hpb, mux),
		canStart: 1, //
	}
	
	miner.Register(NewCpuAgent(hpb.BlockChain(), engine))
	
	go miner.downloaderEventHandle()

	return miner
}


//下载事件的处理，遇到Done和Failed取消订阅，防止DDOS攻击

func (self *Miner) downloaderEventHandle() {
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
out:
	for ev := range events.Chan() {
		switch ev.Data.(type) {
			//下载事件开始，当前的挖矿停止
			case downloader.StartEvent:
				
				log.Info("@@@@@@@@@@@@miner->update->downloader.StartEvent")
	
				atomic.StoreInt32(&self.canStart, 0)
				if self.Mining() {
					self.Stop()
					atomic.StoreInt32(&self.shouldStart, 1)
					log.Info("Mining aborted due to sync")
				}
			//下载事件结束，允许挖矿	
			case downloader.DoneEvent, downloader.FailedEvent:
				shouldStart := atomic.LoadInt32(&self.shouldStart) == 1
				
				log.Info("@@@@@@@@@@@@miner->update--downloader.DoneEvent")
	
				atomic.StoreInt32(&self.canStart, 1) //是否能开始挖矿
				atomic.StoreInt32(&self.shouldStart, 0) //是否可以开始，调整
				if shouldStart {
					self.Start(self.coinbase)
				}
				events.Unsubscribe()
				break out
			}
	}
}

func (self *Miner) Start(coinbase common.Address) {
	log.Info("miner start : ")
	atomic.StoreInt32(&self.shouldStart, 1)
	self.worker.setHpberbase(coinbase)
	self.coinbase = coinbase
	
	// 说明再次被阻断，说明开始的时候被打断
	if atomic.LoadInt32(&self.canStart) == 0 {
		log.Info("Network syncing, will start miner afterwards")
		return
	}
	//设置正在挖矿的标识位
	atomic.StoreInt32(&self.mining, 1)
 
	log.Info("Starting mining operation")
	
	//开始打包的循环
	self.worker.start() 
	
	//开始进行，生成块头
	self.worker.startNewMinerRound()
}

//停止挖矿的方法
func (self *Miner) Stop() {
	//当前的worker通知
	self.worker.stop()
	//设置表示位
	atomic.StoreInt32(&self.mining, 0)
	//设置表示位
	atomic.StoreInt32(&self.shouldStart, 0)
}

func (self *Miner) Register(agent Agent) {
	if self.Mining() {
		agent.Start()
	}
	self.worker.register(agent)
}

func (self *Miner) Unregister(agent Agent) {
	self.worker.unregister(agent)
}

func (self *Miner) Mining() bool {
	return atomic.LoadInt32(&self.mining) > 0
}

func (self *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("Extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	self.worker.setExtra(extra)
	return nil
}


// 获取当前的Pending
func (self *Miner) Pending() (*types.Block, *state.StateDB) {
	return self.worker.pending()
}


// 返回当前的PendingBlock
func (self *Miner) PendingBlock() *types.Block {
	return self.worker.pendingBlock()
}

func (self *Miner) SetHpberbase(addr common.Address) {
	self.coinbase = addr
	self.worker.setHpberbase(addr)
}
