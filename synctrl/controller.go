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
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/prometheus"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/event/sub"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/node/db"
	"github.com/hpb-project/go-hpb/txpool"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	forceSyncCycle      = 10 * time.Second
	minDesiredPeerCount = 5 // Amount of peers desired to start syncing
	txChanSize          = 100000
	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024
)

var (
	reentryMux   sync.Mutex
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

	newBlockMux      *sub.TypeMux
	txCh          chan bc.TxPreEvent
	//txSub         sub.Subscription
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
	if nil == syncInstance {
		reentryMux.Lock()
		if nil == syncInstance {

			intan, err := config.GetHpbConfigInstance()
			if err != nil {
				return nil
			}
			syncInstance, err = newSynCtrl(&intan.BlockChain, intan.Node.SyncMode, txpool.GetTxPool(), prometheus.InstancePrometheus())
			if err != nil {
				syncInstance = nil
			}
		}
		reentryMux.Unlock()
	}

	return syncInstance
}



// NewSynCtrl returns a new block synchronization controller.
func newSynCtrl(cfg *config.ChainConfig, mode config.SyncMode, txpool *txpool.TxPool,
	engine consensus.Engine) (*SynCtrl, error) {
	synctrl := &SynCtrl{
		newBlockMux: new(sub.TypeMux),
		txpool:      txpool,
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
	synctrl.puller = NewPuller(bc.InstanceBlockChain().GetBlockByHash, validator, synctrl.routingBlock, heighter, inserter, synctrl.removePeer)

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
	p2p.PeerMgrInst().RegMsgProcess(p2p.TxMsg, HandleTxMsg)

	p2p.PeerMgrInst().RegOnAddPeer(synctrl.syner.RegisterNetPeer)
	p2p.PeerMgrInst().RegOnDropPeer(synctrl.syner.UnregisterNetPeer)

	return synctrl, nil
}

func (this *SynCtrl) NewBlockMux() *sub.TypeMux{
	return this.newBlockMux
}

func (this *SynCtrl) Start() {
	// broadcast transactions
	this.txCh = make(chan bc.TxPreEvent, txChanSize)
	txPreReceiver := event.RegisterReceiver("synctrl_tx_pre_receiver",
		func(payload interface{}) {
			switch msg := payload.(type) {
			case event.TxPreEvent:
				if ! msg.Message.IsFromP2P() {
					this.txCh <- bc.TxPreEvent{Tx: msg.Message}
				}
			}
		})
	event.Subscribe(txPreReceiver, event.TxPreTopic)
	//this.txSub = this.txpool.SubscribeTxPreEvent(this.txCh)

	go this.txRoutingLoop()

	// broadcast mined blocks
	this.minedBlockSub = this.newBlockMux.Subscribe(bc.NewMinedBlockEvent{})
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
		go this.routingBlock(head, false)
	}
}

func (this *SynCtrl) Syncer() *Syncer {
	return this.syner
}

func (this *SynCtrl) Stop() {
	log.Info("Stopping Hpb data sync")

	//this.txSub.Unsubscribe()         // quits txRoutingLoop
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
		log.Info("######SYN DO REMOVER PEER")
		peer.Disconnect(p2p.DiscUselessPeer)
	}
}

// HandleGetBlockHeadersMsg deal received GetBlockHeadersMsg
func HandleGetBlockHeadersMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the complex header query
	var query getBlockHeadersData
	if err := msg.Decode(&query); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
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

// HandleBlockHeadersMsg deal received BlockHeadersMsg
func HandleBlockHeadersMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of headers arrived to one of our previous requests
	var headers []*types.Header
	if err := msg.Decode(&headers); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}

	// Filter out any explicitly requested headers, deliver the rest to the downloader
	filter := len(headers) == 1
	if filter {
		// Irrelevant of the fork checks, send the header to the fetcher just in case
		headers = InstanceSynCtrl().puller.FilterHeaders(p.GetID(), headers, time.Now())
	}
	if len(headers) > 0 || !filter {
		err := InstanceSynCtrl().syner.DeliverHeaders(p.GetID(), headers)
		if err != nil {
			log.Debug("Failed to deliver headers", "err", err)
		}
	}
	return nil
}

// HandleGetBlockBodiesMsg deal received GetBlockBodiesMsg
func HandleGetBlockBodiesMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather blocks until the fetch or network limits is reached
	var (
		hash   common.Hash
		bytes  int
		bodies []rlp.RawValue
	)
	for bytes < softResponseLimit && len(bodies) < MaxBlockFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested block body, stopping if enough was found
		if data := bc.InstanceBlockChain().GetBodyRLP(hash); len(data) != 0 {
			bodies = append(bodies, data)
			bytes += len(data)
		}
	}
	return sendBlockBodiesRLP(p, bodies)
}

// HandleBlockBodiesMsg deal received BlockBodiesMsg
func HandleBlockBodiesMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of block bodies arrived to one of our previous requests
	var request blockBodiesData
	if err := msg.Decode(&request); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver them all to the downloader for queuing
	trasactions := make([][]*types.Transaction, len(request))
	uncles := make([][]*types.Header, len(request))

	for i, body := range request {
		trasactions[i] = body.Transactions
		uncles[i] = body.Uncles
	}
	// Filter out any explicitly requested bodies, deliver the rest to the downloader
	filter := len(trasactions) > 0 || len(uncles) > 0
	if filter {
		trasactions, uncles = InstanceSynCtrl().puller.FilterBodies(p.GetID(), trasactions, uncles, time.Now())
	}
	if len(trasactions) > 0 || len(uncles) > 0 || !filter {
		err := InstanceSynCtrl().syner.DeliverBodies(p.GetID(), trasactions, uncles)
		if err != nil {
			log.Debug("Failed to deliver bodies", "err", err)
		}
	}
	return nil
}

// HandleGetNodeDataMsg deal received GetNodeDataMsg
func HandleGetNodeDataMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather state data until the fetch or network limits is reached
	var (
		hash  common.Hash
		bytes int
		data  [][]byte
	)
	for bytes < softResponseLimit && len(data) < MaxStateFetch {
		// Retrieve the hash of the next state entry
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested state entry, stopping if enough was found
		if entry, err := db.GetHpbDbInstance().Get(hash.Bytes()); err == nil {
			data = append(data, entry)
			bytes += len(entry)
		}
	}
	return sendNodeData(p, data)
}

// HandleNodeDataMsg deal received NodeDataMsg
func HandleNodeDataMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of node state data arrived to one of our previous requests
	var data [][]byte
	if err := msg.Decode(&data); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := InstanceSynCtrl().syner.DeliverNodeData(p.GetID(), data); err != nil {
		log.Debug("Failed to deliver node state data", "err", err)
	}
	return nil
}

// HandleGetReceiptsMsg deal received GetReceiptsMsg
func HandleGetReceiptsMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather state data until the fetch or network limits is reached
	var (
		hash     common.Hash
		bytes    int
		receipts []rlp.RawValue
	)
	for bytes < softResponseLimit && len(receipts) < MaxReceiptFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested block's receipts, skipping if unknown to us
		results := bc.GetBlockReceipts(db.GetHpbDbInstance(), hash, bc.GetBlockNumber(db.GetHpbDbInstance(), hash))
		if results == nil {
			if header := bc.InstanceBlockChain().GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
				continue
			}
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(results); err != nil {
			log.Error("Failed to encode receipt", "err", err)
		} else {
			receipts = append(receipts, encoded)
			bytes += len(encoded)
		}
	}
	return sendReceiptsRLP(p, receipts)
}

// HandleReceiptsMsg deal received ReceiptsMsg
func HandleReceiptsMsg(p *p2p.Peer, msg p2p.Msg) error {
	// A batch of receipts arrived to one of our previous requests
	var receipts [][]*types.Receipt
	if err := msg.Decode(&receipts); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := InstanceSynCtrl().syner.DeliverReceipts(p.GetID(), receipts); err != nil {
		log.Debug("Failed to deliver receipts", "err", err)
	}
	return nil
}

// HandleNewBlockHashesMsg deal received NewBlockHashesMsg
func HandleNewBlockHashesMsg(p *p2p.Peer, msg p2p.Msg) error {
	var announces newBlockHashesData
	if err := msg.Decode(&announces); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
	}
	// Mark the hashes as present at the remote node
	for _, block := range announces {
		p.KnownBlockAdd(block.Hash)
	}
	// Schedule all the unknown hashes for retrieval
	unknown := make(newBlockHashesData, 0, len(announces))
	for _, block := range announces {
		if !bc.InstanceBlockChain().HasBlock(block.Hash, block.Number) {
			unknown = append(unknown, block)
		}
	}
	for _, block := range unknown {
		InstanceSynCtrl().puller.Notify(p.GetID(), block.Hash, block.Number, time.Now(), requestOneHeader, requestBodies)
	}

	return nil
}

// HandleNewBlockMsg deal received NewBlockMsg
func HandleNewBlockMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Retrieve and decode the propagated block
	var request newBlockData
	if err := msg.Decode(&request); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "%v: %v", msg, err)
	}
	request.Block.ReceivedAt = msg.ReceivedAt
	request.Block.ReceivedFrom = p

	// Mark the peer as owning the block and schedule it for import
	p.KnownBlockAdd(request.Block.Hash())
	InstanceSynCtrl().puller.Enqueue(p.GetID(), request.Block)

	// Assuming the block is importable by the peer, but possibly not yet done so,
	// calculate the head hash and TD that the peer truly must have.
	var (
		trueHead = request.Block.ParentHash()
		trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
	)
	// Update the peers total difficulty if better than the previous
	if _, td := p.Head(); trueTD.Cmp(td) > 0 {
		p.SetHead(trueHead, trueTD)

		// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
		// a singe block (as the true TD is below the propagated block), however this
		// scenario should easily be covered by the fetcher.
		currentBlock := bc.InstanceBlockChain().CurrentBlock()
		if trueTD.Cmp(bc.InstanceBlockChain().GetTd(currentBlock.Hash(), currentBlock.NumberU64())) > 0 {
			go InstanceSynCtrl().synchronise(p)
		}
	}
	return nil
}

// HandleTxMsg deal received TxMsg
func HandleTxMsg(p *p2p.Peer, msg p2p.Msg) error {
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	if atomic.LoadUint32(&InstanceSynCtrl().AcceptTxs) == 0 {
		return nil
	}
	// Transactions can be processed, parse all of them and deliver to the pool
	var txs []*types.Transaction
	if err := msg.Decode(&txs); err != nil {
		return p2p.ErrResp(p2p.ErrDecode, "msg %v: %v", msg, err)
	}
	for i, tx := range txs {
		// Validate and mark the remote transaction
		if tx == nil {
			return p2p.ErrResp(p2p.ErrDecode, "transaction %d is nil", i)
		}
		p.KnownTxsAdd(tx.Hash())
	}
	txpool.GetTxPool().AddTxs(txs)
	return nil
}
