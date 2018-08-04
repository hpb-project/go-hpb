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

// Package miner implements HPB block creation and mining.
package worker

import (
	"fmt"
	"sync/atomic"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/synctrl"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/event/sub"
)


// Miner creates blocks and searches for proof-of-work values.
type Miner struct {
	mux *sub.TypeMux

	worker *worker

	coinbase common.Address
	mining   int32
	engine   consensus.Engine

	canStart    int32 // can start indicates whether we can start the mining operation
	shouldStart int32 // should start indicates whether we should start after sync
}

func New(config *config.ChainConfig, mux *sub.TypeMux, engine consensus.Engine,coinbase common.Address) *Miner {
	miner := &Miner{
		mux:      mux,
		engine:   engine,
		worker:   newWorker(config, engine, coinbase, /*eth,*/ mux),
		canStart: 1,
	}
	miner.Register(NewCpuAgent(bc.InstanceBlockChain(), engine))
	//go miner.update()
	return miner
}

// update keeps track of the synctrl events. Please be aware that this is a one shot type of update loop.
// It's entered once and as soon as `Done` or `Failed` has been broadcasted the events are unregistered and
// the loop is exited. This to prevent a major security vuln where external parties can DOS you with blocks
// and halt your mining operation for as long as the DOS continues.
func (self *Miner) update() {
	events := self.mux.Subscribe(synctrl.StartEvent{}, synctrl.DoneEvent{}, synctrl.FailedEvent{})
out:
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		case synctrl.StartEvent:
			atomic.StoreInt32(&self.canStart, 0)
			if self.Mining() {
				self.Stop()
				atomic.StoreInt32(&self.shouldStart, 1)
				log.Info("Mining aborted due to sync")
			}
		case synctrl.DoneEvent, synctrl.FailedEvent:
			shouldStart := atomic.LoadInt32(&self.shouldStart) == 1

			atomic.StoreInt32(&self.canStart, 1)
			atomic.StoreInt32(&self.shouldStart, 0)
			if shouldStart {
				self.Start(self.coinbase)
			}
			// unsubscribe. we're only interested in this event once
			events.Unsubscribe()
			// stop immediately and ignore all further pending events
			break out
		}
	}
}

func (self *Miner) Start(coinbase common.Address) {
	// 
	go self.update()
	
	atomic.StoreInt32(&self.shouldStart, 1)
	self.worker.setHpberbase(coinbase)
	self.coinbase = coinbase

	if atomic.LoadInt32(&self.canStart) == 0 {
		log.Info("Network syncing, will start miner afterwards")
		return
	}
	atomic.StoreInt32(&self.mining, 1)

	log.Info("Starting mining operation")
	self.worker.start()
	self.worker.startNewMinerRound()
}

func (self *Miner) Stop() {
	self.worker.stop()
	atomic.StoreInt32(&self.mining, 0)
	atomic.StoreInt32(&self.shouldStart, 0)
}

func (self *Miner) Register(producer Producer) {
	if self.Mining() {
		producer.Start()
	}
	self.worker.register(producer)
}

func (self *Miner) Unregister(producer Producer) {
	self.worker.unregister(producer)
}

func (self *Miner) Mining() bool {
	return atomic.LoadInt32(&self.mining) > 0
}

func (self *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > config.MaximumExtraDataSize {
		return fmt.Errorf("Extra exceeds max length. %d > %v", len(extra), config.MaximumExtraDataSize)
	}
	self.worker.setExtra(extra)
	return nil
}

// Pending returns the currently pending block and associated state.
func (self *Miner) Pending() (*types.Block, *state.StateDB) {
	return self.worker.pending()
}

// PendingBlock returns the currently pending block.
//
// Note, to access both the pending block and the pending state
// simultaneously, please use Pending(), as the pending state can
// change between multiple method calls
func (self *Miner) PendingBlock() *types.Block {
	return self.worker.pendingBlock()
}

func (self *Miner) SetHpberbase(addr common.Address) {
	self.coinbase = addr
	self.worker.setHpberbase(addr)
}
