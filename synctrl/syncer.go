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
	"errors"
	"fmt"
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
	hpbinter "github.com/hpb-project/go-hpb/interface"
	"github.com/hpb-project/go-hpb/event/sub"
	"github.com/hpb-project/go-hpb/network/p2p"
)

var (
	MaxHashFetch    = 512 // Amount of hashes to be fetched per retrieval request
	MaxBlockFetch   = 128 // Amount of blocks to be fetched per retrieval request
	MaxHeaderFetch  = 192 // Amount of block headers to be fetched per retrieval request
	MaxSkeletonSize = 128 // Number of header fetches to need for a skeleton assembly
	MaxBodyFetch    = 128 // Amount of block bodies to be fetched per retrieval request
	MaxReceiptFetch = 256 // Amount of transaction receipts to allow fetching per request
	MaxStateFetch   = 384 // Amount of node state values to allow fetching per request

	MaxForkAncestry  = 3 * config.EpochDuration // Maximum chain reorganisation
	rttMinEstimate   = 2 * time.Second          // Minimum round-trip time to target for sync requests
	rttMaxEstimate   = 20 * time.Second         // Maximum rount-trip time to target for sync requests
	rttMinConfidence = 0.1                      // Worse confidence factor in our estimated RTT value
	ttlScaling       = 3                        // Constant scaling factor for RTT -> TTL conversion
	ttlLimit         = time.Minute              // Maximum TTL allowance to prevent reaching crazy timeouts

	qosTuningPeers   = 5    // Number of peers to tune based on (best peers)
	qosConfidenceCap = 10   // Number of peers above which not to modify RTT confidence
	qosTuningImpact  = 0.25 // Impact that a new tuning target has on the previous value

	maxQueuedHeaders  = 32 * 1024 // Maximum number of headers to queue for import (DOS protection)
	maxHeadersProcess = 2048      // Number of header sync results to import at once into the chain
	maxResultsProcess = 2048      // Number of content sync results to import at once into the chain

	fsHeaderCheckFrequency = 100        // Verification frequency of the sync headers during fast sync
	fsHeaderSafetyNet      = 2048       // Number of headers to discard in case a chain violation is detected
	fsHeaderForceVerify    = 24         // Number of headers to verify before and after the pivot to accept it
	fsPivotInterval        = 256        // Number of headers out of which to randomize the pivot point
	fsMinFullBlocks        = 64         // Number of blocks to retrieve fully even in fast sync
	fsCriticalTrials       = uint32(32) // Number of times to retry in the cricical section before bailing
)

var (
	errBusy                    = errors.New("busy")
	errUnknownPeer             = errors.New("peer is unknown or unhealthy")
	errBadPeer                 = errors.New("action from bad peer ignored")
	errStallingPeer            = errors.New("peer is stalling")
	errNoPeers                 = errors.New("no peers to keep sync active")
	errTimeout                 = errors.New("timeout")
	errEmptyHeaderSet          = errors.New("empty header set by peer")
	errPeersUnavailable        = errors.New("no peers available or all tried for sync")
	errInvalidAncestor         = errors.New("retrieved ancestor is invalid")
	errInvalidChain            = errors.New("retrieved hash chain is invalid")
	errInvalidBlock            = errors.New("retrieved block is invalid")
	errInvalidBody             = errors.New("retrieved block body is invalid")
	errInvalidReceipt          = errors.New("retrieved receipt is invalid")
	errCancelBlockFetch        = errors.New("block sync canceled (requested)")
	errCancelHeaderFetch       = errors.New("block header sync canceled (requested)")
	errCancelBodyFetch         = errors.New("block body sync canceled (requested)")
	errCancelReceiptFetch      = errors.New("receipt sync canceled (requested)")
	errCancelStateFetch        = errors.New("state data sync canceled (requested)")
	errCancelHeaderProcessing  = errors.New("header processing canceled (requested)")
	errCancelContentProcessing = errors.New("content processing canceled (requested)")
	errNoSyncActive            = errors.New("no sync active")
	errProVLowerBase           = errors.New(fmt.Sprintf("peer is lower than the current baseline version (need Minimum version >= %d)", config.ProtocolV111))
	errTooOld                  = errors.New("peer doesn't speak recent enough protocol version (need version >= 62)")
)

// LightChain encapsulates functions required to synchronise a light chain.
type LightChain interface {
	// HasHeader verifies a header's presence in the local chain.
	HasHeader(h common.Hash, number uint64) bool

	// GetHeaderByHash retrieves a header from the local chain.
	GetHeaderByHash(common.Hash) *types.Header

	// CurrentHeader retrieves the head header from the local chain.
	CurrentHeader() *types.Header

	// GetTdByHash returns the total difficulty of a local block.
	GetTdByHash(common.Hash) *big.Int

	// InsertHeaderChain inserts a batch of headers into the local chain.
	InsertHeaderChain([]*types.Header, int) (int, error)

	// Rollback removes a few recently added elements from the local chain.
	Rollback([]common.Hash)
}

// BlockChain encapsulates functions required to sync a (full or fast) blockchain.
type BlockChain interface {
	LightChain

	// HasBlockAndState verifies block and associated states' presence in the local chain.
	HasBlockAndState(common.Hash) bool

	// GetBlockByHash retrieves a block from the local chain.
	GetBlockByHash(common.Hash) *types.Block

	// CurrentBlock retrieves the head block from the local chain.
	CurrentBlock() *types.Block

	// CurrentFastBlock retrieves the head fast block from the local chain.
	CurrentFastBlock() *types.Block

	// FastSyncCommitHead directly commits the head block to a certain entity.
	FastSyncCommitHead(common.Hash) error

	// InsertChain inserts a batch of blocks into the local chain.
	InsertChain(types.Blocks) (int, error)

	// InsertReceiptChain inserts a batch of receipts into the local chain.
	InsertReceiptChain(types.Blocks, []types.Receipts) (int, error)
}

type syncStrategy interface {
	deliverHeaders(id string, headers []*types.Header) (err error)
	deliverBodies(id string, transactions [][]*types.Transaction,
		uncles [][]*types.Header) (err error)
	deliverReceipts(id string, receipts [][]*types.Receipt) (err error)
	deliverNodeData(id string, data [][]byte) (err error)

	syncWithPeer(id string, p *peerConnection, hash common.Hash, td *big.Int) (err error)
	cancel()

	registerPeer(id string, version uint, peer Peer) error
	registerLightPeer(id string, version uint, peer LightPeer) error
	unregisterPeer(id string) error
}

type Syncer struct {
	mode         config.SyncMode       // Synchronisation mode defining the strategy used (per sync cycle)
	strategy     syncStrategy

	mux     *sub.TypeMux // Event multiplexer to announce sync operation events
	stateDB hpbdb.Database
	lightchain LightChain

	peers   *peerSet // Set of active peers from which sync can proceed
	dropPeer peerDropFn // Drops a peer for misbehaving
	sch     *scheduler   // Scheduler for selecting the hashes to sync

	// Statistics
	syncStatsChainOrigin uint64 // Origin block number where syncing started at
	syncStatsChainHeight uint64 // Highest block number known when syncing started

	rttEstimate   uint64 // Round trip time to target for sync requests
	rttConfidence uint64 // Confidence in the estimated RTT (unit: millionths to allow atomic ops)

	// for stateFetcher
	stateSyncStart chan *stateSync
	trackStateReq  chan *stateReq
	stateCh        chan dataPack // Channel receiving inbound node state data
	syncStatsState stateSyncStats
	syncStatsLock  sync.RWMutex // Lock protecting the sync stats fields
	// Status
	synchroniseMock func(id string, hash common.Hash) error // Replacement for synchronise during testing
	synchronising   int32
	notified        int32
	fsPivotFails uint32        // Number of subsequent fast sync failures in the critical section

	quitLock sync.RWMutex  // Lock to prevent double closes
	quitCh   chan struct{} // Quit channel to signal termination
}

func NewSyncer(mode config.SyncMode, stateDb hpbdb.Database, mux *sub.TypeMux, lightchain LightChain,
	dropPeer peerDropFn) *Syncer {
	if lightchain == nil {
		lightchain = bc.InstanceBlockChain()
	}
	syn := &Syncer{
		mode:           mode,
		stateDB:        stateDb,
		mux:            mux,
		lightchain:     lightchain,
		peers:          newPeerSet(),
		dropPeer:       dropPeer,
		sch:            newScheduler(),
		rttEstimate:    uint64(rttMaxEstimate),
		rttConfidence:  uint64(1000000),
		quitCh:         make(chan struct{}),
		stateCh:        make(chan dataPack),
		stateSyncStart: make(chan *stateSync),
		trackStateReq:  make(chan *stateReq),
	}
	switch mode {
	case config.FullSync:
		syn.strategy = newFullsync(syn)
	case config.FastSync:
		syn.strategy = newFastsync(syn)
	case config.LightSync:
		syn.strategy = newLightsync(syn)
	default:
		syn.strategy = nil
	}

	go syn.qosTuner()
	go syn.stateFetcher()

	return syn
}

// Progress retrieves the synchronisation boundaries, specifically the origin
// block where synchronisation started at (may have failed/suspended); the block
// or header sync is currently at; and the latest known block which the sync targets.
//
// In addition, during the state sync phase of fast synchronisation the number
// of processed and the total number of known states are also returned. Otherwise
// these are zero.
func (this *Syncer) Progress() hpbinter.SyncProgress {
	// Lock the current stats and return the progress
	this.syncStatsLock.RLock()
	defer this.syncStatsLock.RUnlock()

	current := bc.InstanceBlockChain().CurrentBlock().NumberU64()
	return hpbinter.SyncProgress{
		StartingBlock: this.syncStatsChainOrigin,
		CurrentBlock:  current,
		HighestBlock:  this.syncStatsChainHeight,
		PulledStates:  this.syncStatsState.processed,
		KnownStates:   this.syncStatsState.processed + this.syncStatsState.pending,
	}
}

// Start tries to sync up our local block chain with a remote peer, both
// adding various sanity checks as well as wrapping it with various log entries.
func (this *Syncer) Start(id string, head common.Hash, td *big.Int, mode config.SyncMode) error {
	err := this.syn(id, head, td, mode)
	switch err {
	case nil:
	case errBusy:

	case errTimeout, errBadPeer, errStallingPeer,
		errEmptyHeaderSet, errPeersUnavailable, errProVLowerBase,
		errInvalidAncestor, errInvalidChain:
		log.Warn("Synchronisation failed, dropping peer", "peer", id, "err", err)
		this.dropPeer(id)

	default:
		log.Warn("Synchronisation failed, retrying", "err", err)
	}
	return err
}

// syn will select the peer and use it for synchronising. If an empty string is given
// it will use the best peer possible and synchronize if it's TD is higher than our own. If any of the
// checks fail an error will be returned. This method is synchronous
func (this *Syncer) syn(id string, hash common.Hash, td *big.Int, mode config.SyncMode) error {
	// Mock out the synchronisation if testing
	if this.synchroniseMock != nil {
		return this.synchroniseMock(id, hash)
	}
	// Make sure only one goroutine is ever allowed past this point at once
	if !atomic.CompareAndSwapInt32(&this.synchronising, 0, 1) {
		return errBusy
	}
	defer atomic.StoreInt32(&this.synchronising, 0)

	// Post a user notification of the sync (only once per session)
	if atomic.CompareAndSwapInt32(&this.notified, 0, 1) {
		log.Info("Block synchronisation started")
	}
	// Reset the sch, peer set and wake channels to clean any internal leftover state
	this.sch.Reset()
	this.peers.Reset()

	// Set the requested sync mode, unless it's forbidden
	this.mode = mode
	if this.mode == config.FastSync && atomic.LoadUint32(&this.fsPivotFails) >= fsCriticalTrials {
		// stop the previous synchronization strategy
		this.strategy.cancel()
		this.strategy = newFullsync(this)
	}
	// Retrieve the origin peer and initiate the syncing process
	p := this.peers.Peer(id)
	if p == nil {
		return errUnknownPeer
	}
	return this.strategy.syncWithPeer(id, p, hash, td)
}

// Terminate interrupts the syn, canceling all pending operations.
// The syncer cannot be reused after calling Terminate.
func (this *Syncer) terminate() {
	// Close the termination channel (make sure double close is allowed)
	this.quitLock.Lock()
	select {
	case <-this.quitCh:
	default:
		close(this.quitCh)
	}
	this.quitLock.Unlock()

	// Cancel any pending sync requests
	this.strategy.cancel()
}

// Synchronising returns whether the syn is currently retrieving blocks.
func (this *Syncer) Synchronising() bool {
	return atomic.LoadInt32(&this.synchronising) > 0
}

// RegisterPeer injects a new syn peer into the set of block source to be
// used for fetching hashes and blocks from.
func (this *Syncer) RegisterPeer(id string, version uint, peer Peer) error {
	return this.strategy.registerPeer(id, version, peer)
}
func (this *Syncer) RegisterNetPeer(peer *p2p.Peer) error {
	ps := &PeerSyn{peer}
	ps.Log().Info("register network peer in syncer.")
	return this.RegisterPeer(ps.GetID(), ps.GetVersion(), ps)
}

// RegisterLightPeer injects a light client peer, wrapping it so it appears as a regular peer.
func (this *Syncer) RegisterLightPeer(id string, version uint, peer LightPeer) error {
	return this.RegisterPeer(id, version, &lightPeerWrapper{peer})
}

// UnregisterPeer remove a peer from the known list, preventing any action from
// the specified peer. An effort is also made to return any pending fetches into
// the queue.
func (this *Syncer) UnregisterPeer(id string) error {
	return this.strategy.unregisterPeer(id)
}

func (this *Syncer) UnregisterNetPeer(peer *p2p.Peer) error {
	peer.Log().Info("register network peer in syncer.")
	return this.UnregisterPeer(peer.GetID())
}

// Cancel cancels all of the operations and resets the scheduler. It returns true
// if the cancel operation was completed.
func (this *Syncer) Cancel() {
	this.strategy.cancel()
}

// DeliverHeaders injects a new batch of block headers received from a remote
// node into the syn schedule.
func (this *Syncer) DeliverHeaders(id string, headers []*types.Header) (err error) {
	return this.strategy.deliverHeaders(id, headers)
}

// DeliverBodies injects a new batch of block bodies received from a remote node.
func (this *Syncer) DeliverBodies(id string, transactions [][]*types.Transaction, uncles [][]*types.Header) (err error) {
	return this.strategy.deliverBodies(id, transactions, uncles)
}

// DeliverReceipts injects a new batch of receipts received from a remote node.
func (this *Syncer) DeliverReceipts(id string, receipts [][]*types.Receipt) (err error) {
	return this.strategy.deliverReceipts(id, receipts)
}

// DeliverNodeData injects a new batch of node state data received from a remote node.
func (this *Syncer) DeliverNodeData(id string, data [][]byte) (err error) {
	return this.strategy.deliverNodeData(id, data)
}


// qosTuner is the quality of service tuning loop that occasionally gathers the
// peer latency statistics and updates the estimated request round trip time.
func (this *Syncer) qosTuner() {
	for {
		// Retrieve the current median RTT and integrate into the previoust target RTT
		rtt := time.Duration(float64(1-qosTuningImpact)*float64(atomic.LoadUint64(&this.rttEstimate)) + qosTuningImpact*float64(this.peers.medianRTT()))
		atomic.StoreUint64(&this.rttEstimate, uint64(rtt))

		// A new RTT cycle passed, increase our confidence in the estimated RTT
		conf := atomic.LoadUint64(&this.rttConfidence)
		conf = conf + (1000000-conf)/2
		atomic.StoreUint64(&this.rttConfidence, conf)

		// Log the new QoS values and sleep until the next RTT
		log.Debug("Recalculated syncer QoS values", "rtt", rtt, "confidence", float64(conf)/1000000.0, "ttl", this.requestTTL())
		select {
		case <-this.quitCh:
			return
		case <-time.After(rtt):
		}
	}
}

// requestTTL returns the current timeout allowance for a single sync request
// to finish under.
func (this *Syncer) requestTTL() time.Duration {
	var (
		rtt  = time.Duration(atomic.LoadUint64(&this.rttEstimate))
		conf = float64(atomic.LoadUint64(&this.rttConfidence)) / 1000000.0
	)
	ttl := time.Duration(ttlScaling) * time.Duration(float64(rtt)/conf)
	if ttl > ttlLimit {
		ttl = ttlLimit
	}
	return ttl
}

// stateFetcher manages the active state sync and accepts requests
// on its behalf.
func (this *Syncer) stateFetcher() {
	for {
		select {
		case s := <-this.stateSyncStart:
			for next := s; next != nil; {
				next = this.runStateSync(next)
			}
		case <-this.stateCh:
			// Ignore state responses while no sync is running.
		case <-this.quitCh:
			return
		}
	}
}

// runStateSync runs a state synchronisation until it completes or another root
// hash is requested to be switched over to.
func (this *Syncer) runStateSync(s *stateSync) *stateSync {
	var (
		active   = make(map[string]*stateReq) // Currently in-flight requests
		finished []*stateReq                  // Completed or failed requests
		timeout  = make(chan *stateReq)       // Timed out active requests
	)
	defer func() {
		// Cancel active request timers on exit. Also set peers to idle so they're
		// available for the next sync.
		for _, req := range active {
			req.timer.Stop()
			req.peer.SetNodeDataIdle(len(req.items))
		}
	}()
	// Run the state sync.
	go s.run()
	defer s.Cancel()

	// Listen for peer departure events to cancel assigned tasks
	peerDrop := make(chan *peerConnection, 1024)
	peerSub := s.syn.peers.SubscribePeerDrops(peerDrop)
	defer peerSub.Unsubscribe()

	for {
		// Enable sending of the first buffered element if there is one.
		var (
			deliverReq   *stateReq
			deliverReqCh chan *stateReq
		)
		if len(finished) > 0 {
			deliverReq = finished[0]
			deliverReqCh = s.deliver
		}

		select {
		// The stateSync lifecycle:
		case next := <-this.stateSyncStart:
			return next

		case <-s.done:
			return nil

			// Send the next finished request to the current sync:
		case deliverReqCh <- deliverReq:
			finished = append(finished[:0], finished[1:]...)

			// Handle incoming state packs:
		case pack := <-this.stateCh:
			// Discard any data not requested (or previsouly timed out)
			req := active[pack.PeerId()]
			if req == nil {
				log.Debug("Unrequested node data", "peer", pack.PeerId(), "len", pack.Items())
				continue
			}
			// Finalize the request and queue up for processing
			req.timer.Stop()
			req.response = pack.(*statePack).states

			finished = append(finished, req)
			delete(active, pack.PeerId())

			// Handle dropped peer connections:
		case p := <-peerDrop:
			// Skip if no request is currently pending
			req := active[p.id]
			if req == nil {
				continue
			}
			// Finalize the request and queue up for processing
			req.timer.Stop()
			req.dropped = true

			finished = append(finished, req)
			delete(active, p.id)

			// Handle timed-out requests:
		case req := <-timeout:
			// If the peer is already requesting something else, ignore the stale timeout.
			// This can happen when the timeout and the delivery happens simultaneously,
			// causing both pathways to trigger.
			if active[req.peer.id] != req {
				continue
			}
			// Move the timed out data back into the light sync queue
			finished = append(finished, req)
			delete(active, req.peer.id)

			// Track outgoing state requests:
		case req := <-this.trackStateReq:
			// If an active request already exists for this peer, we have a problem. In
			// theory the trie node schedule must never assign two requests to the same
			// peer. In practive however, a peer might receive a request, disconnect and
			// immediately reconnect before the previous times out. In this case the first
			// request is never honored, alas we must not silently overwrite it, as that
			// causes valid requests to go missing and sync to get stuck.
			if old := active[req.peer.id]; old != nil {
				log.Warn("Busy peer assigned new state fetch", "peer", old.peer.id)

				// Make sure the previous one doesn't get siletly lost
				old.timer.Stop()
				old.dropped = true

				finished = append(finished, old)
			}
			// Start a timer to notify the sync loop if the peer stalled.
			req.timer = time.AfterFunc(req.timeout, func() {
				select {
				case timeout <- req:
				case <-s.done:
					// Prevent leaking of timer goroutines in the unlikely case where a
					// timer is fired just before exiting runStateSync.
				}
			})
			active[req.peer.id] = req
		}
	}
}