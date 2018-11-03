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

// Contains the block download scheduler to collect download tasks and schedule
// them in an ordered, and throttled way.

package synctrl

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/rcrowley/go-metrics"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

var blockCacheLimit = 8192 // Maximum number of blocks to cache before throttling the download

var (
	errNoFetchesPending = errors.New("no fetches pending")
	errStaleDelivery    = errors.New("stale delivery")
)

// fetchRequest is a currently running data retrieval operation.
type fetchRequest struct {
	Peer    *peerConnection     // Peer to which the request was sent
	From    uint64              // Requested chain element index (used for skeleton fills only)
	Hashes  map[common.Hash]int // Requested hashes with their insertion index (priority)
	Headers []*types.Header     // Requested headers, sorted by request order
	Time    time.Time           // Time when the request was made
}

// fetchResult is a struct collecting partial results from data fetchers until
// all outstanding pieces complete and the result as a whole can be processed.
type fetchResult struct {
	Pending int // Number of data fetches still pending

	Header       *types.Header
	Uncles       []*types.Header
	Transactions types.Transactions
	Receipts     types.Receipts
}

// queue represents hashes that are either need fetching or are being fetched
type scheduler struct {
	mode          config.SyncMode // Synchronisation mode to decide on the block parts to schedule for fetching
	fastSyncPivot uint64          // Block number where the fast sync pivots into archive synchronisation mode

	headerHead common.Hash // Hash of the last queued header to verify order

	// Headers are "special", they download in batches, supported by a skeleton chain
	headerTaskPool  map[uint64]*types.Header       // Pending header retrieval tasks, mapping starting indexes to skeleton headers
	headerTaskQueue *prque.Prque                   // Priority queue of the skeleton indexes to fetch the filling headers for
	headerPeerMiss  map[string]map[uint64]struct{} // Set of per-peer header batches known to be unavailable
	headerPendPool  map[string]*fetchRequest       // Currently pending header retrieval operations
	headerResults   []*types.Header                // Result cache accumulating the completed headers
	headerProced    int                            // Number of headers already processed from the results
	headerOffset    uint64                         // Number of the first header in the result cache
	headerContCh    chan bool                      // Channel to notify when header download finishes

	// All data retrievals below are based on an already assembles header chain
	blockTaskPool  map[common.Hash]*types.Header // Pending block (body) retrieval tasks, mapping hashes to headers
	blockTaskQueue *prque.Prque                  // Priority queue of the headers to fetch the blocks (bodies) for
	blockPendPool  map[string]*fetchRequest      // Currently pending block (body) retrieval operations
	blockDonePool  map[common.Hash]struct{}      // Set of the completed block (body) fetches

	receiptTaskPool  map[common.Hash]*types.Header // Pending receipt retrieval tasks, mapping hashes to headers
	receiptTaskQueue *prque.Prque                  // Priority queue of the headers to fetch the receipts for
	receiptPendPool  map[string]*fetchRequest      // Currently pending receipt retrieval operations
	receiptDonePool  map[common.Hash]struct{}      // Set of the completed receipt fetches

	resultCache  []*fetchResult // Downloaded but not yet delivered fetch results
	resultOffset uint64         // Offset of the first cached fetch result in the block chain

	lock   *sync.Mutex
	active *sync.Cond
	closed bool
}

// newScheduler creates a new syn scheduler for scheduling block retrieval.
func newScheduler() *scheduler {
	lock := new(sync.Mutex)
	return &scheduler{
		headerPendPool:   make(map[string]*fetchRequest),
		headerContCh:     make(chan bool),
		blockTaskPool:    make(map[common.Hash]*types.Header),
		blockTaskQueue:   prque.New(),
		blockPendPool:    make(map[string]*fetchRequest),
		blockDonePool:    make(map[common.Hash]struct{}),
		receiptTaskPool:  make(map[common.Hash]*types.Header),
		receiptTaskQueue: prque.New(),
		receiptPendPool:  make(map[string]*fetchRequest),
		receiptDonePool:  make(map[common.Hash]struct{}),
		resultCache:      make([]*fetchResult, blockCacheLimit),
		active:           sync.NewCond(lock),
		lock:             lock,
	}
}

// Reset clears out the queue contents.
func (this *scheduler) Reset() {
	this.lock.Lock()
	defer this.lock.Unlock()

	this.closed = false
	this.mode = config.FullSync
	this.fastSyncPivot = 0

	this.headerHead = common.Hash{}

	this.headerPendPool = make(map[string]*fetchRequest)

	this.blockTaskPool = make(map[common.Hash]*types.Header)
	this.blockTaskQueue.Reset()
	this.blockPendPool = make(map[string]*fetchRequest)
	this.blockDonePool = make(map[common.Hash]struct{})

	this.receiptTaskPool = make(map[common.Hash]*types.Header)
	this.receiptTaskQueue.Reset()
	this.receiptPendPool = make(map[string]*fetchRequest)
	this.receiptDonePool = make(map[common.Hash]struct{})

	this.resultCache = make([]*fetchResult, blockCacheLimit)
	this.resultOffset = 0
}

// Close marks the end of the sync, unblocking WaitResults.
// It may be called even if the queue is already closed.
func (this *scheduler) Close() {
	this.lock.Lock()
	this.closed = true
	this.lock.Unlock()
	this.active.Broadcast()
}

// PendingHeaders retrieves the number of header requests pending for retrieval.
func (this *scheduler) PendingHeaders() int {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.headerTaskQueue.Size()
}

// PendingBlocks retrieves the number of block (body) requests pending for retrieval.
func (this *scheduler) PendingBlocks() int {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.blockTaskQueue.Size()
}

// PendingReceipts retrieves the number of block receipts pending for retrieval.
func (this *scheduler) PendingReceipts() int {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.receiptTaskQueue.Size()
}

// InFlightHeaders retrieves whether there are header fetch requests currently
// in flight.
func (this *scheduler) InFlightHeaders() bool {
	this.lock.Lock()
	defer this.lock.Unlock()

	return len(this.headerPendPool) > 0
}

// InFlightBlocks retrieves whether there are block fetch requests currently in
// flight.
func (this *scheduler) InFlightBlocks() bool {
	this.lock.Lock()
	defer this.lock.Unlock()

	return len(this.blockPendPool) > 0
}

// InFlightReceipts retrieves whether there are receipt fetch requests currently
// in flight.
func (this *scheduler) InFlightReceipts() bool {
	this.lock.Lock()
	defer this.lock.Unlock()

	return len(this.receiptPendPool) > 0
}

// Idle returns if the queue is fully idle or has some data still inside.
func (this *scheduler) Idle() bool {
	this.lock.Lock()
	defer this.lock.Unlock()

	queued := this.blockTaskQueue.Size() + this.receiptTaskQueue.Size()
	pending := len(this.blockPendPool) + len(this.receiptPendPool)
	cached := len(this.blockDonePool) + len(this.receiptDonePool)

	return (queued + pending + cached) == 0
}

// FastSyncPivot retrieves the currently used fast sync pivot point.
func (this *scheduler) FastSyncPivot() uint64 {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.fastSyncPivot
}

// ShouldThrottleBlocks checks if the download should be throttled (active block (body)
// fetches exceed block cache).
func (this *scheduler) ShouldThrottleBlocks() bool {
	this.lock.Lock()
	defer this.lock.Unlock()

	// Calculate the currently in-flight block (body) requests
	pending := 0
	for _, request := range this.blockPendPool {
		pending += len(request.Hashes) + len(request.Headers)
	}
	// Throttle if more blocks (bodies) are in-flight than free space in the cache
	return pending >= len(this.resultCache)-len(this.blockDonePool)
}

// ShouldThrottleReceipts checks if the download should be throttled (active receipt
// fetches exceed block cache).
func (this *scheduler) ShouldThrottleReceipts() bool {
	this.lock.Lock()
	defer this.lock.Unlock()

	// Calculate the currently in-flight receipt requests
	pending := 0
	for _, request := range this.receiptPendPool {
		pending += len(request.Headers)
	}
	// Throttle if more receipts are in-flight than free space in the cache
	return pending >= len(this.resultCache)-len(this.receiptDonePool)
}

// ScheduleSkeleton adds a batch of header retrieval tasks to the queue to fill
// up an already retrieved header skeleton.
func (this *scheduler) ScheduleSkeleton(from uint64, skeleton []*types.Header) {
	this.lock.Lock()
	defer this.lock.Unlock()

	// No skeleton retrieval can be in progress, fail hard if so (huge implementation bug)
	if this.headerResults != nil {
		panic("skeleton assembly already in progress")
	}
	// Shedule all the header retrieval tasks for the skeleton assembly
	this.headerTaskPool = make(map[uint64]*types.Header)
	this.headerTaskQueue = prque.New()
	this.headerPeerMiss = make(map[string]map[uint64]struct{}) // Reset availability to correct invalid chains
	this.headerResults = make([]*types.Header, len(skeleton)*MaxHeaderFetch)
	this.headerProced = 0
	this.headerOffset = from
	this.headerContCh = make(chan bool, 1)

	for i, header := range skeleton {
		index := from + uint64(i*MaxHeaderFetch)

		this.headerTaskPool[index] = header
		this.headerTaskQueue.Push(index, -float32(index))
	}
}

// RetrieveHeaders retrieves the header chain assemble based on the scheduled
// skeleton.
func (this *scheduler) RetrieveHeaders() ([]*types.Header, int) {
	this.lock.Lock()
	defer this.lock.Unlock()

	headers, proced := this.headerResults, this.headerProced
	this.headerResults, this.headerProced = nil, 0

	return headers, proced
}

// Schedule adds a set of headers for the download queue for scheduling, returning
// the new headers encountered.
func (this *scheduler) Schedule(headers []*types.Header, from uint64) []*types.Header {
	this.lock.Lock()
	defer this.lock.Unlock()

	// Insert all the headers prioritised by the contained block number
	inserts := make([]*types.Header, 0, len(headers))
	for _, header := range headers {
		// Make sure chain order is honoured and preserved throughout
		hash := header.Hash()
		if header.Number == nil || header.Number.Uint64() != from {
			log.Warn("Header broke chain ordering", "number", header.Number, "hash", hash, "expected", from)
			break
		}
		if this.headerHead != (common.Hash{}) && this.headerHead != header.ParentHash {
			log.Warn("Header broke chain ancestry", "number", header.Number, "hash", hash)
			break
		}
		// Make sure no duplicate requests are executed
		if _, ok := this.blockTaskPool[hash]; ok {
			log.Warn("Header  already scheduled for block fetch", "number", header.Number, "hash", hash)
			continue
		}
		if _, ok := this.receiptTaskPool[hash]; ok {
			log.Warn("Header already scheduled for receipt fetch", "number", header.Number, "hash", hash)
			continue
		}
		// Queue the header for content retrieval
		this.blockTaskPool[hash] = header
		this.blockTaskQueue.Push(header, -float32(header.Number.Uint64()))

		if this.mode == config.FastSync && header.Number.Uint64() <= this.fastSyncPivot {
			// Fast phase of the fast sync, retrieve receipts too
			this.receiptTaskPool[hash] = header
			this.receiptTaskQueue.Push(header, -float32(header.Number.Uint64()))
		}
		inserts = append(inserts, header)
		this.headerHead = hash
		from++
	}
	return inserts
}

// WaitResults retrieves and permanently removes a batch of fetch
// results from the cache. the result slice will be empty if the queue
// has been closed.
func (this *scheduler) WaitResults() []*fetchResult {
	this.lock.Lock()
	defer this.lock.Unlock()

	nproc := this.countProcessableItems()
	for nproc == 0 && !this.closed {
		this.active.Wait()
		nproc = this.countProcessableItems()
	}
	results := make([]*fetchResult, nproc)
	copy(results, this.resultCache[:nproc])
	if len(results) > 0 {
		// Mark results as done before dropping them from the cache.
		for _, result := range results {
			hash := result.Header.Hash()
			delete(this.blockDonePool, hash)
			delete(this.receiptDonePool, hash)
		}
		// Delete the results from the cache and clear the tail.
		copy(this.resultCache, this.resultCache[nproc:])
		for i := len(this.resultCache) - nproc; i < len(this.resultCache); i++ {
			this.resultCache[i] = nil
		}
		// Advance the expected block number of the first cache entry.
		this.resultOffset += uint64(nproc)
	}
	return results
}

// countProcessableItems counts the processable items.
func (this *scheduler) countProcessableItems() int {
	for i, result := range this.resultCache {
		// Don't process incomplete or unavailable items.
		if result == nil || result.Pending > 0 {
			return i
		}
		// Stop before processing the pivot block to ensure that
		// resultCache has space for fsHeaderForceVerify items. Not
		// doing this could leave us unable to download the required
		// amount of headers.
		if this.mode == config.FastSync && result.Header.Number.Uint64() == this.fastSyncPivot {
			for j := 0; j < fsHeaderForceVerify; j++ {
				if i+j+1 >= len(this.resultCache) || this.resultCache[i+j+1] == nil {
					return i
				}
			}
		}
	}
	return len(this.resultCache)
}

// ReserveHeaders reserves a set of headers for the given peer, skipping any
// previously failed batches.
func (this *scheduler) ReserveHeaders(p *peerConnection, count int) *fetchRequest {
	this.lock.Lock()
	defer this.lock.Unlock()

	// Short circuit if the peer's already downloading something (sanity check to
	// not corrupt state)
	if _, ok := this.headerPendPool[p.id]; ok {
		return nil
	}
	// Retrieve a batch of hashes, skipping previously failed ones
	send, skip := uint64(0), []uint64{}
	for send == 0 && !this.headerTaskQueue.Empty() {
		from, _ := this.headerTaskQueue.Pop()
		if this.headerPeerMiss[p.id] != nil {
			if _, ok := this.headerPeerMiss[p.id][from.(uint64)]; ok {
				skip = append(skip, from.(uint64))
				continue
			}
		}
		send = from.(uint64)
	}
	// Merge all the skipped batches back
	for _, from := range skip {
		this.headerTaskQueue.Push(from, -float32(from))
	}
	// Assemble and return the block download request
	if send == 0 {
		return nil
	}
	request := &fetchRequest{
		Peer: p,
		From: send,
		Time: time.Now(),
	}
	this.headerPendPool[p.id] = request
	return request
}

// ReserveBodies reserves a set of body fetches for the given peer, skipping any
// previously failed downloads. Beside the next batch of needed fetches, it also
// returns a flag whether empty blocks were queued requiring processing.
func (this *scheduler) ReserveBodies(p *peerConnection, count int) (*fetchRequest, bool, error) {
	isNoop := func(header *types.Header) bool {
		return header.TxHash == types.EmptyRootHash && header.UncleHash == types.EmptyUncleHash
	}
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.reserveHeaders(p, count, this.blockTaskPool, this.blockTaskQueue, this.blockPendPool, this.blockDonePool, isNoop)
}

// ReserveReceipts reserves a set of receipt fetches for the given peer, skipping
// any previously failed downloads. Beside the next batch of needed fetches, it
// also returns a flag whether empty receipts were queued requiring importing.
func (this *scheduler) ReserveReceipts(p *peerConnection, count int) (*fetchRequest, bool, error) {
	isNoop := func(header *types.Header) bool {
		return header.ReceiptHash == types.EmptyRootHash
	}
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.reserveHeaders(p, count, this.receiptTaskPool, this.receiptTaskQueue, this.receiptPendPool, this.receiptDonePool, isNoop)
}

// reserveHeaders reserves a set of data download operations for a given peer,
// skipping any previously failed ones. This method is a generic version used
// by the individual special reservation functions.
//
// Note, this method expects the queue lock to be already held for writing. The
// reason the lock is not obtained in here is because the parameters already need
// to access the queue, so they already need a lock anyway.
func (this *scheduler) reserveHeaders(p *peerConnection, count int, taskPool map[common.Hash]*types.Header, taskQueue *prque.Prque,
	pendPool map[string]*fetchRequest, donePool map[common.Hash]struct{}, isNoop func(*types.Header) bool) (*fetchRequest, bool, error) {
	// Short circuit if the pool has been depleted, or if the peer's already
	// downloading something (sanity check not to corrupt state)
	if taskQueue.Empty() {
		return nil, false, nil
	}
	if _, ok := pendPool[p.id]; ok {
		return nil, false, nil
	}
	// Calculate an upper limit on the items we might fetch (i.e. throttling)
	space := len(this.resultCache) - len(donePool)
	for _, request := range pendPool {
		space -= len(request.Headers)
	}
	// Retrieve a batch of tasks, skipping previously failed ones
	send := make([]*types.Header, 0, count)
	skip := make([]*types.Header, 0)

	progress := false
	for proc := 0; proc < space && len(send) < count && !taskQueue.Empty(); proc++ {
		header := taskQueue.PopItem().(*types.Header)

		// If we're the first to request this task, initialise the result container
		index := int(header.Number.Int64() - int64(this.resultOffset))
		if index >= len(this.resultCache) || index < 0 {
			common.Report("index allocation went beyond available resultCache space")
			log.Error("invalid hash chain(reserveHeaders)", "index", index, "len(resultCache)", len(this.resultCache))
			return nil, false, errInvalidChain
		}
		if this.resultCache[index] == nil {
			components := 1
			if this.mode == config.FastSync && header.Number.Uint64() <= this.fastSyncPivot {
				components = 2
			}
			this.resultCache[index] = &fetchResult{
				Pending: components,
				Header:  header,
			}
		}
		// If this fetch task is a noop, skip this fetch operation
		if isNoop(header) {
			donePool[header.Hash()] = struct{}{}
			delete(taskPool, header.Hash())

			space, proc = space-1, proc-1
			this.resultCache[index].Pending--
			progress = true
			continue
		}
		// Otherwise unless the peer is known not to have the data, add to the retrieve list
		if p.Lacks(header.Hash()) {
			skip = append(skip, header)
		} else {
			send = append(send, header)
		}
	}
	// Merge all the skipped headers back
	for _, header := range skip {
		taskQueue.Push(header, -float32(header.Number.Uint64()))
	}
	if progress {
		// Wake WaitResults, resultCache was modified
		this.active.Signal()
	}
	// Assemble and return the block download request
	if len(send) == 0 {
		return nil, progress, nil
	}
	request := &fetchRequest{
		Peer:    p,
		Headers: send,
		Time:    time.Now(),
	}
	pendPool[p.id] = request

	return request, progress, nil
}

// CancelHeaders aborts a fetch request, returning all pending skeleton indexes to the queue.
func (this *scheduler) CancelHeaders(request *fetchRequest) {
	this.cancel(request, this.headerTaskQueue, this.headerPendPool)
}

// CancelBodies aborts a body fetch request, returning all pending headers to the
// task queue.
func (this *scheduler) CancelBodies(request *fetchRequest) {
	this.cancel(request, this.blockTaskQueue, this.blockPendPool)
}

// CancelReceipts aborts a body fetch request, returning all pending headers to
// the task queue.
func (this *scheduler) CancelReceipts(request *fetchRequest) {
	this.cancel(request, this.receiptTaskQueue, this.receiptPendPool)
}

// Cancel aborts a fetch request, returning all pending hashes to the task queue.
func (this *scheduler) cancel(request *fetchRequest, taskQueue *prque.Prque, pendPool map[string]*fetchRequest) {
	this.lock.Lock()
	defer this.lock.Unlock()

	if request.From > 0 {
		taskQueue.Push(request.From, -float32(request.From))
	}
	for hash, index := range request.Hashes {
		taskQueue.Push(hash, float32(index))
	}
	for _, header := range request.Headers {
		taskQueue.Push(header, -float32(header.Number.Uint64()))
	}
	delete(pendPool, request.Peer.id)
}

// Revoke cancels all pending requests belonging to a given peer. This method is
// meant to be called during a peer drop to quickly reassign owned data fetches
// to remaining nodes.
func (this *scheduler) Revoke(peerId string) {
	this.lock.Lock()
	defer this.lock.Unlock()

	if request, ok := this.blockPendPool[peerId]; ok {
		for _, header := range request.Headers {
			this.blockTaskQueue.Push(header, -float32(header.Number.Uint64()))
		}
		delete(this.blockPendPool, peerId)
	}
	if request, ok := this.receiptPendPool[peerId]; ok {
		for _, header := range request.Headers {
			this.receiptTaskQueue.Push(header, -float32(header.Number.Uint64()))
		}
		delete(this.receiptPendPool, peerId)
	}
}

// ExpireHeaders checks for in flight requests that exceeded a timeout allowance,
// canceling them and returning the responsible peers for penalisation.
func (this *scheduler) ExpireHeaders(timeout time.Duration) map[string]int {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.expire(timeout, this.headerPendPool, this.headerTaskQueue, headerTimeoutMeter)
}

// ExpireBodies checks for in flight block body requests that exceeded a timeout
// allowance, canceling them and returning the responsible peers for penalisation.
func (this *scheduler) ExpireBodies(timeout time.Duration) map[string]int {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.expire(timeout, this.blockPendPool, this.blockTaskQueue, bodyTimeoutMeter)
}

// ExpireReceipts checks for in flight receipt requests that exceeded a timeout
// allowance, canceling them and returning the responsible peers for penalisation.
func (this *scheduler) ExpireReceipts(timeout time.Duration) map[string]int {
	this.lock.Lock()
	defer this.lock.Unlock()

	return this.expire(timeout, this.receiptPendPool, this.receiptTaskQueue, receiptTimeoutMeter)
}

// expire is the generic check that move expired tasks from a pending pool back
// into a task pool, returning all entities caught with expired tasks.
//
// Note, this method expects the queue lock to be already held. The
// reason the lock is not obtained in here is because the parameters already need
// to access the queue, so they already need a lock anyway.
func (this *scheduler) expire(timeout time.Duration, pendPool map[string]*fetchRequest, taskQueue *prque.Prque, timeoutMeter metrics.Meter) map[string]int {
	// Iterate over the expired requests and return each to the queue
	expiries := make(map[string]int)
	for id, request := range pendPool {
		if time.Since(request.Time) > timeout {
			// Update the metrics with the timeout
			timeoutMeter.Mark(1)

			// Return any non satisfied requests to the pool
			if request.From > 0 {
				taskQueue.Push(request.From, -float32(request.From))
			}
			for hash, index := range request.Hashes {
				taskQueue.Push(hash, float32(index))
			}
			for _, header := range request.Headers {
				taskQueue.Push(header, -float32(header.Number.Uint64()))
			}
			// Add the peer to the expiry report along the the number of failed requests
			expirations := len(request.Hashes)
			if expirations < len(request.Headers) {
				expirations = len(request.Headers)
			}
			expiries[id] = expirations
		}
	}
	// Remove the expired requests from the pending pool
	for id := range expiries {
		delete(pendPool, id)
	}
	return expiries
}

// DeliverHeaders injects a header retrieval response into the header results
// cache. This method either accepts all headers it received, or none of them
// if they do not map correctly to the skeleton.
//
// If the headers are accepted, the method makes an attempt to deliver the set
// of ready headers to the processor to keep the pipeline full. However it will
// not block to prevent stalling other pending deliveries.
func (this *scheduler) DeliverHeaders(id string, headers []*types.Header, headerProcCh chan []*types.Header) (int, error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	// Short circuit if the data was never requested
	request := this.headerPendPool[id]
	if request == nil {
		return 0, errNoFetchesPending
	}
	headerReqTimer.UpdateSince(request.Time)
	delete(this.headerPendPool, id)

	// Ensure headers can be mapped onto the skeleton chain
	target := this.headerTaskPool[request.From].Hash()

	accepted := len(headers) == MaxHeaderFetch
	if accepted {
		if headers[0].Number.Uint64() != request.From {
			log.Trace("First header broke chain ordering", "peer", id, "number", headers[0].Number, "hash", headers[0].Hash(), request.From)
			accepted = false
		} else if headers[len(headers)-1].Hash() != target {
			log.Trace("Last header broke skeleton structure ", "peer", id, "number", headers[len(headers)-1].Number, "hash", headers[len(headers)-1].Hash(), "expected", target)
			accepted = false
		}
	}
	if accepted {
		for i, header := range headers[1:] {
			hash := header.Hash()
			if want := request.From + 1 + uint64(i); header.Number.Uint64() != want {
				log.Warn("Header broke chain ordering", "peer", id, "number", header.Number, "hash", hash, "expected", want)
				accepted = false
				break
			}
			if headers[i].Hash() != header.ParentHash {
				log.Warn("Header broke chain ancestry", "peer", id, "number", header.Number, "hash", hash)
				accepted = false
				break
			}
		}
	}
	// If the batch of headers wasn't accepted, mark as unavailable
	if !accepted {
		log.Trace("Skeleton filling not accepted", "peer", id, "from", request.From)

		miss := this.headerPeerMiss[id]
		if miss == nil {
			this.headerPeerMiss[id] = make(map[uint64]struct{})
			miss = this.headerPeerMiss[id]
		}
		miss[request.From] = struct{}{}

		this.headerTaskQueue.Push(request.From, -float32(request.From))
		return 0, errors.New("delivery not accepted")
	}
	// Clean up a successful fetch and try to deliver any sub-results
	copy(this.headerResults[request.From-this.headerOffset:], headers)
	delete(this.headerTaskPool, request.From)

	ready := 0
	for this.headerProced+ready < len(this.headerResults) && this.headerResults[this.headerProced+ready] != nil {
		ready += MaxHeaderFetch
	}
	if ready > 0 {
		// Headers are ready for delivery, gather them and push forward (non blocking)
		process := make([]*types.Header, ready)
		copy(process, this.headerResults[this.headerProced:this.headerProced+ready])

		select {
		case headerProcCh <- process:
			log.Trace("Pre-scheduled new headers", "peer", id, "count", len(process), "from", process[0].Number)
			this.headerProced += len(process)
		default:
		}
	}
	// Check for termination and return
	if len(this.headerTaskPool) == 0 {
		this.headerContCh <- false
	}
	return len(headers), nil
}

// DeliverBodies injects a block body retrieval response into the results queue.
// The method returns the number of blocks bodies accepted from the delivery and
// also wakes any threads waiting for data delivery.
func (this *scheduler) DeliverBodies(id string, txLists [][]*types.Transaction, uncleLists [][]*types.Header) (int, error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	reconstruct := func(header *types.Header, index int, result *fetchResult) error {
		if types.DeriveSha(types.Transactions(txLists[index])) != header.TxHash || types.CalcUncleHash(uncleLists[index]) != header.UncleHash {
			return errInvalidBody
		}
		result.Transactions = txLists[index]
		result.Uncles = uncleLists[index]
		return nil
	}
	return this.deliver(id, this.blockTaskPool, this.blockTaskQueue, this.blockPendPool, this.blockDonePool, bodyReqTimer, len(txLists), reconstruct)
}

// DeliverReceipts injects a receipt retrieval response into the results queue.
// The method returns the number of transaction receipts accepted from the delivery
// and also wakes any threads waiting for data delivery.
func (this *scheduler) DeliverReceipts(id string, receiptList [][]*types.Receipt) (int, error) {
	this.lock.Lock()
	defer this.lock.Unlock()

	reconstruct := func(header *types.Header, index int, result *fetchResult) error {
		if types.DeriveSha(types.Receipts(receiptList[index])) != header.ReceiptHash {
			return errInvalidReceipt
		}
		result.Receipts = receiptList[index]
		return nil
	}
	return this.deliver(id, this.receiptTaskPool, this.receiptTaskQueue, this.receiptPendPool, this.receiptDonePool, receiptReqTimer, len(receiptList), reconstruct)
}

// deliver injects a data retrieval response into the results queue.
//
// Note, this method expects the queue lock to be already held for writing. The
// reason the lock is not obtained in here is because the parameters already need
// to access the queue, so they already need a lock anyway.
func (this *scheduler) deliver(id string, taskPool map[common.Hash]*types.Header, taskQueue *prque.Prque,
	pendPool map[string]*fetchRequest, donePool map[common.Hash]struct{}, reqTimer metrics.Timer,
	results int, reconstruct func(header *types.Header, index int, result *fetchResult) error) (int, error) {

	// Short circuit if the data was never requested
	request := pendPool[id]
	if request == nil {
		return 0, errNoFetchesPending
	}
	reqTimer.UpdateSince(request.Time)
	delete(pendPool, id)

	// If no data items were retrieved, mark them as unavailable for the origin peer
	if results == 0 {
		for _, header := range request.Headers {
			request.Peer.MarkLacking(header.Hash())
		}
	}
	// Assemble each of the results with their headers and retrieved data parts
	var (
		accepted int
		failure  error
		useful   bool
	)
	for i, header := range request.Headers {
		// Short circuit assembly if no more fetch results are found
		if i >= results {
			break
		}
		// Reconstruct the next result if contents match up
		index := int(header.Number.Int64() - int64(this.resultOffset))
		if index >= len(this.resultCache) || index < 0 || this.resultCache[index] == nil {
			failure = errInvalidChain
			log.Error("invalid hash chain(deliver)", "index", index, "len(resultCache)", len(this.resultCache))
			break
		}
		if err := reconstruct(header, i, this.resultCache[index]); err != nil {
			failure = err
			break
		}
		donePool[header.Hash()] = struct{}{}
		this.resultCache[index].Pending--
		useful = true
		accepted++

		// Clean up a successful fetch
		request.Headers[i] = nil
		delete(taskPool, header.Hash())
	}
	// Return all failed or missing fetches to the queue
	for _, header := range request.Headers {
		if header != nil {
			taskQueue.Push(header, -float32(header.Number.Uint64()))
		}
	}
	// Wake up WaitResults
	if accepted > 0 {
		this.active.Signal()
	}
	// If none of the data was good, it's a stale delivery
	switch {
	case failure == nil || failure == errInvalidChain:
		return accepted, failure
	case useful:
		return accepted, fmt.Errorf("partial failure: %v", failure)
	default:
		return accepted, errStaleDelivery
	}
}

// Prepare configures the result cache to allow accepting and caching inbound
// fetch results.
func (this *scheduler) Prepare(offset uint64, mode config.SyncMode, pivot uint64, head *types.Header) {
	this.lock.Lock()
	defer this.lock.Unlock()

	// Prepare the queue for sync results
	if this.resultOffset < offset {
		this.resultOffset = offset
	}
	this.fastSyncPivot = pivot
	this.mode = mode
}
