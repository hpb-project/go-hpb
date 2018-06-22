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
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/event/sub"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/txpool"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	forceSyncCycle      = 10 * time.Second
	minDesiredPeerCount = 5 // Amount of peers desired to start syncing
	txChanSize = 100000
	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024
)

// SyncMode represents the synchronisation mode of the downloader.
type SyncMode int

const (
	FullSync  SyncMode = iota // Synchronise the entire blockchain history from full blocks
	FastSync                  // Quickly download the headers, full sync only at the chain head
	LightSync                 // Download only the headers and terminate afterwards
)

func (mode SyncMode) IsValid() bool {
	return mode >= FullSync && mode <= LightSync
}

// String implements the stringer interface.
func (mode SyncMode) String() string {
	switch mode {
	case FullSync:
		return "full"
	case FastSync:
		return "fast"
	case LightSync:
		return "light"
	default:
		return "unknown"
	}
}

func (mode SyncMode) MarshalText() ([]byte, error) {
	switch mode {
	case FullSync:
		return []byte("full"), nil
	case FastSync:
		return []byte("fast"), nil
	case LightSync:
		return []byte("light"), nil
	default:
		return nil, fmt.Errorf("unknown sync mode %d", mode)
	}
}

func (mode *SyncMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "full":
		*mode = FullSync
	case "fast":
		*mode = FastSync
	case "light":
		*mode = LightSync
	default:
		return fmt.Errorf(`unknown sync mode %q, want "full", "fast" or "light"`, text)
	}
	return nil
}

type DoneEvent struct{}
type StartEvent struct{}
type FailedEvent struct{ Err error }

type SynCtrl struct {
	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	AcceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      *txpool.TxPool //todo xinqyu's
	chaindb     hpbdb.Database
	chainconfig *config.ChainConfig
	maxPeers    int

	syner       *Syncer
	puller      *Puller

	SubProtocols []p2p.Protocol

	eventMux      *sub.TypeMux
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

// NewSynCtrl returns a new block synchronization controller.
func NewSynCtrl(config *config.ChainConfig, mode SyncMode, networkId uint64, mux *sub.TypeMux, txpool *txpool.TxPool,/*todo txpool*/
	engine consensus.Engine, chaindb hpbdb.Database) (*SynCtrl, error) {
	synctrl := &SynCtrl{
		eventMux:    mux,
		txpool:      txpool,
		chaindb:     chaindb,
		chainconfig: config,
		newPeerCh:   make(chan *p2p.Peer),//todo
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
	}

	if mode == FastSync && bc.InstanceBlockChain().CurrentBlock().NumberU64() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = FullSync
	}
	if mode == FastSync {
		synctrl.fastSync = uint32(1)
	}
	// Construct the different synchronisation mechanisms
	synctrl.syner = NewSyncer(mode, chaindb, synctrl.eventMux, nil, synctrl.removePeer)//todo removePeer

	validator := func(header *types.Header) error {
		return engine.VerifyHeader(bc.InstanceBlockChain(), header, true)
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
	synctrl.puller = NewPuller(bc.InstanceBlockChain().GetBlockByHash, validator, synctrl.routingBlock, heighter, inserter, synctrl.removePeer)//todo removerPeer

	return synctrl, nil
}

func (this *SynCtrl) Start() {
	// broadcast transactions
	this.txCh = make(chan bc.TxPreEvent, txChanSize)
	this.txSub = this.txpool.SubscribeTxPreEvent(this.txCh)//todo by xinyu
	go this.txRoutingLoop()

	// broadcast mined blocks
	this.minedBlockSub = this.eventMux.Subscribe(bc.NewMinedBlockEvent{})
	go this.minedRoutingLoop()

	// start sync handlers
	go this.sync()
	go this.txsyncLoop()
}

// Mined routing loop
func (this *SynCtrl) minedRoutingLoop() {
	// automatically stops if unsubscribe
	for obj := range this.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case bc.NewMinedBlockEvent:
			this.routingBlock(ev.Block, true)  // First propagate block to peers
			this.routingBlock(ev.Block, false) // Only then announce to the rest
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
			// Make sure we have peers to select from, then sync
			if p2p.PeerMgrInst().Len() < minDesiredPeerCount {
				break
			}
			go this.synchronise(p2p.PeerMgrInst().BestPeer())

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
	if peer == nil {
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
	mode := FullSync
	if atomic.LoadUint32(&this.fastSync) == 1 {
		// Fast sync was explicitly requested, and explicitly granted
		mode = FastSync
	} else if currentBlock.NumberU64() == 0 && bc.InstanceBlockChain().CurrentFastBlock().NumberU64() > 0 {
		// The database seems empty as the current block is the genesis. Yet the fast
		// block is ahead, so fast sync was enabled for this node at a certain point.
		// The only scenario where this can happen is if the user manually (or via a
		// bad block) rolled back a fast sync node below the sync point. In this case
		// however it's safe to reenable fast sync.
		atomic.StoreUint32(&this.fastSync, 1)
		mode = FastSync
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
		go this.routingBlock(head, false)
	}
}

func (this *SynCtrl) Stop() {
	log.Info("Stopping Hpb data sync")

	this.txSub.Unsubscribe()         // quits txRoutingLoop
	this.minedBlockSub.Unsubscribe() // quits minedRoutingLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	this.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(this.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	p2p.PeerMgrInst().Close()

	// Wait for all peer handler goroutines and the loops to come down.
	this.wg.Wait()

	log.Info("Hpb data sync stopped")
}

// routingBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (this *SynCtrl) routingBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := p2p.PeerMgrInst().PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := bc.InstanceBlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), bc.InstanceBlockChain().GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			switch peer.LocalType() {
			case discover.PreNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlock(peer, block, td)
					break
				default:
					break
				}
				break
			case discover.HpNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlock(peer, block, td)
					break
				case discover.HpNode:
					sendNewBlock(peer, block, td)
					break
				default:
					break
				}
				break
			default:
				break
			}
		}
		log.Trace("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if bc.InstanceBlockChain().HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			switch peer.LocalType() {
			case discover.PreNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				default:
					break
				}
				break
			case discover.HpNode:
				switch peer.RemoteType() {
				case discover.PreNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				case discover.HpNode:
					sendNewBlockHashes(peer, []common.Hash{hash}, []uint64{block.NumberU64()})
					break
				default:
					break
				}
				break
			default:
				break
			}
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
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
	if err := p2p.PeerMgrInst().Unregister(id); err != nil {
		log.Error("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func HandleGetBlockHeadersMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the complex header query
	var query getBlockHeadersData
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "%v: %v", msg, err)
	}
	hashMode := query.Origin.Hash != (common.Hash{})

	// Gather headers until the fetch or network limits is reached
	var (
		bytes   common.StorageSize
		headers []*types.Header
		unknown bool
	)
	for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < MaxHeaderFetch {
		// Retrieve the next header satisfying the query
		var origin *types.Header
		if hashMode {
			origin = bc.InstanceBlockChain().GetHeaderByHash(query.Origin.Hash)
		} else {
			origin = bc.InstanceBlockChain().GetHeaderByNumber(query.Origin.Number)
		}
		if origin == nil {
			break
		}
		number := origin.Number.Uint64()
		headers = append(headers, origin)
		bytes += estHeaderRlpSize

		// Advance to the next header of the query
		switch {
		case query.Origin.Hash != (common.Hash{}) && query.Reverse:
			// Hash based traversal towards the genesis block
			for i := 0; i < int(query.Skip)+1; i++ {
				if header := bc.InstanceBlockChain().GetHeader(query.Origin.Hash, number); header != nil {
					query.Origin.Hash = header.ParentHash
					number--
				} else {
					unknown = true
					break
				}
			}
		case query.Origin.Hash != (common.Hash{}) && !query.Reverse:
			// Hash based traversal towards the leaf block
			var (
				current = origin.Number.Uint64()
				next    = current + query.Skip + 1
			)
			if next <= current {
				infos, _ := json.MarshalIndent(p.Info(), "", "  ")
				p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
				unknown = true
			} else {
				if header := bc.InstanceBlockChain().GetHeaderByNumber(next); header != nil {
					if bc.InstanceBlockChain().GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
						query.Origin.Hash = header.Hash()
					} else {
						unknown = true
					}
				} else {
					unknown = true
				}
			}
		case query.Reverse:
			// Number based traversal towards the genesis block
			if query.Origin.Number >= query.Skip+1 {
				query.Origin.Number -= (query.Skip + 1)
			} else {
				unknown = true
			}

		case !query.Reverse:
			// Number based traversal towards the leaf block
			query.Origin.Number += (query.Skip + 1)
		}
	}
	return sendBlockHeaders(p, headers)
}