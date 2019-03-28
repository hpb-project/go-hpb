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

package synctrl

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/prometheus"
	"github.com/hpb-project/go-hpb/event/sub"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/node/db"
	"github.com/hpb-project/go-hpb/txpool"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	forceSyncCycle = 10 * time.Second
	txChanSize     = 100000
	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024
)

var (
	once         sync.Once
	syncInstance *SynCtrl
)

type DoneEvent struct{}
type StartEvent struct{}
type FailedEvent struct{ Err error }

type SynCtrl struct {
	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	AcceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      *txpool.TxPool
	chainconfig *config.ChainConfig
	maxPeers    int

	syner  *Syncer
	puller *Puller

	SubProtocols []p2p.Protocol

	newBlockMux   *sub.TypeMux
	txCh          chan bc.TxPreEvent
	txSub         sub.Subscription
	minedBlockSub *sub.TypeMuxSubscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *p2p.Peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
}

// InstanceSynCtrl returns the singleton of SynCtrl.
func InstanceSynCtrl() *SynCtrl {
	once.Do(func() {
		i, err := newSynCtrl(&config.GetHpbConfigInstance().BlockChain, config.GetHpbConfigInstance().Node.SyncMode, txpool.GetTxPool(), prometheus.InstancePrometheus())
		if err != nil {
			log.Error("Failed to instance SynCtrl", "err", err)
		}
		syncInstance = i
	})
	return syncInstance
}

// NewSynCtrl returns a new block synchronization controller.
func newSynCtrl(cfg *config.ChainConfig, mode config.SyncMode, txpoolins *txpool.TxPool,
	engine consensus.Engine) (*SynCtrl, error) {
	synctrl := &SynCtrl{
		newBlockMux: new(sub.TypeMux),
		txpool:      txpoolins,
		chainconfig: cfg,
		newPeerCh:   make(chan *p2p.Peer),
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
	}

	if mode == config.FastSync && bc.InstanceBlockChain().CurrentBlock().NumberU64() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = config.FullSync
	}
	if mode == config.FastSync {
		synctrl.fastSync = uint32(1)
	}
	// Construct the different synchronisation mechanisms
	synctrl.syner = NewSyncer(mode, db.GetHpbDbInstance(), synctrl.newBlockMux, nil, synctrl.removePeer)

	validator := func(header *types.Header) error {
		return engine.VerifyHeader(bc.InstanceBlockChain(), header, true, mode)
	}
	heighter := func() uint64 {
		return bc.InstanceBlockChain().CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		// If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&synctrl.fastSync) == 1 {
			log.Warn("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
			return 0, nil
		}
		atomic.StoreUint32(&synctrl.AcceptTxs, 1) // Mark initial sync done on any fetcher import
		return bc.InstanceBlockChain().InsertChain(blocks)
	}
	synctrl.puller = NewPuller(bc.InstanceBlockChain().GetBlockByHash, validator, routBlock, heighter, inserter, synctrl.removePeer)

	p2p.PeerMgrInst().RegMsgProcess(p2p.GetBlockHeadersMsg, HandleGetBlockHeadersMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.GetBlockBodiesMsg, HandleGetBlockBodiesMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.BlockHeadersMsg, HandleBlockHeadersMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.BlockBodiesMsg, HandleBlockBodiesMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.GetNodeDataMsg, HandleGetNodeDataMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.NodeDataMsg, HandleNodeDataMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.GetReceiptsMsg, HandleGetReceiptsMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.ReceiptsMsg, HandleReceiptsMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.NewBlockHashesMsg, HandleNewBlockHashesMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.NewBlockMsg, HandleNewBlockMsg)
	p2p.PeerMgrInst().RegMsgProcess(p2p.NewHashBlockMsg, HandleNewHashBlockMsg)

	p2p.PeerMgrInst().RegMsgProcess(p2p.TxMsg, HandleTxMsg)

	p2p.PeerMgrInst().RegOnAddPeer(synctrl.RegisterNetPeer)
	p2p.PeerMgrInst().RegOnDropPeer(synctrl.UnregisterNetPeer)

	return synctrl, nil
}

func (this *SynCtrl) NewBlockMux() *sub.TypeMux {
	return this.newBlockMux
}

func (this *SynCtrl) Start() {
	// broadcast transactions
	this.txCh = make(chan bc.TxPreEvent, txChanSize)
	this.txSub = this.txpool.SubscribeTxPreEvent(this.txCh)

	go this.txRoutingLoop()

	// broadcast mined blocks
	this.minedBlockSub = this.newBlockMux.Subscribe(bc.NewMinedBlockEvent{})
	go this.minedRoutingLoop()

	// start sync handlers
	go this.sync()
	go this.txsyncLoop()
}

func (this *SynCtrl) RegisterNetPeer(peer *p2p.Peer) error {
	ps := &PeerSyn{peer}
	this.syncTransactions(peer)
	log.Debug("register net peer","pid",peer.GetID())

	err := this.syner.RegisterPeer(peer.GetID(), peer.GetVersion(), ps)
	if err != nil {
		return err
	}

	// start new peer syn
	time.Sleep(time.Millisecond*10)
	this.newPeerCh <- peer
	return nil
}

func (this *SynCtrl) UnregisterNetPeer(peer *p2p.Peer) error {
	log.Debug("unregister net peer","pid",peer.GetID())
	return this.syner.UnregisterPeer(peer.GetID())
}

// Mined routing loop
func (this *SynCtrl) minedRoutingLoop() {
	// automatically stops if unsubscribe
	for obj := range this.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case bc.NewMinedBlockEvent:
			routBlock(ev.Block, true)  // First propagate block to peers
			routBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}

// syncer is responsible for periodically synchronising with the network, both
// downloading hashes and blocks as well as handling the announcement handler.
func (this *SynCtrl) sync() {
	// Start and ensure cleanup of sync mechanisms
	this.puller.start()
	defer this.puller.stop()
	defer this.syner.terminate()

	// Wait for different events to fire synchronisation operations
	forceSync := time.NewTicker(forceSyncCycle)
	defer forceSync.Stop()

	for {
		select {
		case <-this.newPeerCh:
		case <-forceSync.C:
			// Force a sync even if not enough peers are present
			go this.synchronise(p2p.PeerMgrInst().BestPeer())

		case <-this.noMorePeers:
			return
		}
	}
}

// synchronise tries to sync up our local block chain with a remote peer.
func (this *SynCtrl) synchronise(peer *p2p.Peer) {
	// Short circuit if no peers are available
	if peer == nil || peer.LocalType() == discover.BootNode {
		return
	}
	// Make sure the peer's TD is higher than our own
	currentBlock := bc.InstanceBlockChain().CurrentBlock()
	td := bc.InstanceBlockChain().GetTd(currentBlock.Hash(), currentBlock.NumberU64())

	pHead, pTd := peer.Head()

	if pTd.Cmp(td) <= 0 {
		return
	}
	// Otherwise try to sync with the downloader
	mode := config.FullSync
	if atomic.LoadUint32(&this.fastSync) == 1 {
		// Fast sync was explicitly requested, and explicitly granted
		mode = config.FastSync
	} else if currentBlock.NumberU64() == 0 && bc.InstanceBlockChain().CurrentFastBlock().NumberU64() > 0 {
		// The database seems empty as the current block is the genesis. Yet the fast
		// block is ahead, so fast sync was enabled for this node at a certain point.
		// The only scenario where this can happen is if the user manually (or via a
		// bad block) rolled back a fast sync node below the sync point. In this case
		// however it's safe to reenable fast sync.
		atomic.StoreUint32(&this.fastSync, 1)
		mode = config.FastSync
	}
	// Run the sync cycle, and disable fast sync if we've went past the pivot block
	err := this.syner.Start(peer.GetID(), pHead, pTd, mode)

	if atomic.LoadUint32(&this.fastSync) == 1 {
		// Disable fast sync if we indeed have something in our chain
		if bc.InstanceBlockChain().CurrentBlock().NumberU64() > 0 {
			atomic.StoreUint32(&this.fastSync, 0)
		}
	}
	if err != nil {
		return
	}
	atomic.StoreUint32(&this.AcceptTxs, 1) // Mark initial sync done
	if head := bc.InstanceBlockChain().CurrentBlock(); head.NumberU64() > 0 {
		// We've completed a sync cycle, notify all peers of new state. This path is
		// essential in star-topology networks where a gateway node needs to notify
		// all its out-of-date peers of the availability of a new block. This failure
		// scenario will most often crop up in private and hackathon networks with
		// degenerate connectivity, but it should be healthy for the mainnet too to
		// more reliably update peers or the local TD state.
		go routBlock(head, false)
	}
}

func (this *SynCtrl) Syncer() *Syncer {
	return this.syner
}

func (this *SynCtrl) Stop() {
	log.Debug("Stopping Hpb data sync")

	this.txSub.Unsubscribe()         // quits txRoutingLoop
	this.minedBlockSub.Unsubscribe() // quits minedRoutingLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	this.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(this.quitSync)

	// Wait for all peer handler goroutines and the loops to come down.
	this.wg.Wait()

	log.Info("Hpb data sync stopped")
}

func (this *SynCtrl) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := p2p.PeerMgrInst().Peer(id)
	if peer == nil {
		return
	}
	log.Debug("Removing Hpb peer", "peer", id)

	// Unregister the peer from the downloader and Hpb peer set
	this.syner.UnregisterPeer(id)

	// Hard disconnect at the networking layer
	if peer != nil {
		log.Error("###### SYN DO REMOVER PEER ######", "peer", id)
		peer.Disconnect(p2p.DiscPeerBySyn)
	}
}
