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
	"fmt"
	"hash"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto/sha3"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/trie"
)

// stateReq represents a batch of state fetch requests groupped together into
// a single data retrieval network packet.
type stateReq struct {
	items    []common.Hash              // Hashes of the state items to download
	tasks    map[common.Hash]*stateTask // Download tasks to track previous attempts
	timeout  time.Duration              // Maximum round trip time for this to complete
	timer    *time.Timer                // Timer to fire when the RTT timeout expires
	peer     *peerConnection            // Peer that we're requesting from
	response [][]byte                   // Response data of the peer (nil for timeouts)
	dropped  bool                       // Flag whether the peer dropped off early
}

// timedOut returns if this request timed out.
func (req *stateReq) timedOut() bool {
	return req.response == nil
}

// stateSyncStats is a collection of progress stats to report during a state trie
// sync to RPC requests as well as to display in user logs.
type stateSyncStats struct {
	processed  uint64 // Number of state entries processed
	duplicate  uint64 // Number of state entries downloaded twice
	unexpected uint64 // Number of non-requested state entries received
	pending    uint64 // Number of still pending state entries
}

// stateSync schedules requests for downloading a particular state trie defined
// by a given state root.
type stateSync struct {
	syn    *Syncer // syncer instance to access and manage current peerset

	sched  *trie.TrieSync             // State trie sync scheduler defining the tasks
	keccak hash.Hash                  // Keccak256 hasher to verify deliveries with
	tasks  map[common.Hash]*stateTask // Set of tasks currently queued for retrieval

	numUncommitted   int
	bytesUncommitted int

	deliver    chan *stateReq // Delivery channel multiplexing peer responses
	cancel     chan struct{}  // Channel to signal a termination request
	cancelOnce sync.Once      // Ensures cancel only ever gets called once
	done       chan struct{}  // Channel to signal termination completion
	err        error          // Any error hit during sync (set before completion)
}

// stateTask represents a single trie node download taks, containing a set of
// peers already attempted retrieval from to detect stalled syncs and abort.
type stateTask struct {
	attempts map[string]struct{}
}

// newStateSync creates a new state trie download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newStateSync(syn *Syncer, root common.Hash) *stateSync {
	return &stateSync{
		syn:     syn,
		sched:   state.NewStateSync(root, syn.stateDB),
		keccak:  sha3.NewKeccak256(),
		tasks:   make(map[common.Hash]*stateTask),
		deliver: make(chan *stateReq),
		cancel:  make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// run starts the task assignment and response processing loop, blocking until
// it finishes, and finally notifying any goroutines waiting for the loop to
// finish.
func (s *stateSync) run() {
	s.err = s.loop()
	close(s.done)
}

// Wait blocks until the sync is done or canceled.
func (s *stateSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
func (s *stateSync) Cancel() error {
	s.cancelOnce.Do(func() { close(s.cancel) })
	return s.Wait()
}

// loop is the main event loop of a state trie sync. It it responsible for the
// assignment of new tasks to peers (including sending it to them) as well as
// for the processing of inbound data. Note, that the loop does not directly
// receive data from peers, rather those are buffered up in the downloader and
// pushed here async. The reason is to decouple processing from data receipt
// and timeouts.
func (s *stateSync) loop() error {
	// Listen for new peer events to assign tasks to them
	newPeer := make(chan *peerConnection, 1024)
	peerSub := s.syn.peers.SubscribeNewPeers(newPeer)
	defer peerSub.Unsubscribe()

	// Keep assigning new tasks until the sync completes or aborts
	for s.sched.Pending() > 0 {
		if err := s.commit(false); err != nil {
			return err
		}
		s.assignTasks()
		// Tasks assigned, wait for something to happen
		select {
		case <-newPeer:
			// New peer arrived, try to assign it download tasks

		case <-s.cancel:
			return errCancelStateFetch

		case req := <-s.deliver:
			// Response, disconnect or timeout triggered, drop the peer if stalling
			log.Trace("Received node data response", "peer", req.peer.id, "count", len(req.response), "dropped", req.dropped, "timeout", !req.dropped && req.timedOut())
			if len(req.items) <= 2 && !req.dropped && req.timedOut() {
				// 2 items are the minimum requested, if even that times out, we've no use of
				// this peer at the moment.
				log.Warn("Stalling state sync, dropping peer", "peer", req.peer.id)
				s.syn.dropPeer(req.peer.id)
			}
			// Process all the received blobs and check for stale delivery
			stale, err := s.process(req)
			if err != nil {
				log.Warn("Node data write error", "err", err)
				return err
			}
			// The the delivery contains requested data, mark the node idle (otherwise it's a timed out delivery)
			if !stale {
				req.peer.SetNodeDataIdle(len(req.response))
			}
		}
	}
	return s.commit(true)
}

func (s *stateSync) commit(force bool) error {
	if !force && s.bytesUncommitted < hpbdb.IdealBatchSize {
		return nil
	}
	start := time.Now()
	b := s.syn.stateDB.NewBatch()
	s.sched.Commit(b)
	if err := b.Write(); err != nil {
		return fmt.Errorf("DB write error: %v", err)
	}
	s.updateStats(s.numUncommitted, 0, 0, time.Since(start))
	s.numUncommitted = 0
	s.bytesUncommitted = 0
	return nil
}

// assignTasks attempts to assing new tasks to all idle peers, either from the
// batch currently being retried, or fetching new data from the trie sync itself.
func (s *stateSync) assignTasks() {
	// Iterate over all idle peers and try to assign them state fetches
	peers, _ := s.syn.peers.NodeDataIdlePeers()
	for _, p := range peers {
		// Assign a batch of fetches proportional to the estimated latency/bandwidth
		cap := p.NodeDataCapacity(s.syn.requestTTL())
		req := &stateReq{peer: p, timeout: s.syn.requestTTL()}
		s.fillTasks(cap, req)

		// If the peer was assigned tasks to fetch, send the network request
		if len(req.items) > 0 {
			req.peer.log.Trace("Requesting new batch of data", "type", "state", "count", len(req.items))
			select {
			case s.syn.trackStateReq <- req:
				req.peer.FetchNodeData(req.items)
			case <-s.cancel:
			}
		}
	}
}

// fillTasks fills the given request object with a maximum of n state download
// tasks to send to the remote peer.
func (s *stateSync) fillTasks(n int, req *stateReq) {
	// Refill available tasks from the scheduler.
	if len(s.tasks) < n {
		new := s.sched.Missing(n - len(s.tasks))
		for _, hash := range new {
			s.tasks[hash] = &stateTask{make(map[string]struct{})}
		}
	}
	// Find tasks that haven't been tried with the request's peer.
	req.items = make([]common.Hash, 0, n)
	req.tasks = make(map[common.Hash]*stateTask, n)
	for hash, t := range s.tasks {
		// Stop when we've gathered enough requests
		if len(req.items) == n {
			break
		}
		// Skip any requests we've already tried from this peer
		if _, ok := t.attempts[req.peer.id]; ok {
			continue
		}
		// Assign the request to this peer
		t.attempts[req.peer.id] = struct{}{}
		req.items = append(req.items, hash)
		req.tasks[hash] = t
		delete(s.tasks, hash)
	}
}

// process iterates over a batch of delivered state data, injecting each item
// into a running state sync, re-queuing any items that were requested but not
// delivered.
func (s *stateSync) process(req *stateReq) (bool, error) {
	// Collect processing stats and update progress if valid data was received
	duplicate, unexpected := 0, 0

	defer func(start time.Time) {
		if duplicate > 0 || unexpected > 0 {
			s.updateStats(0, duplicate, unexpected, time.Since(start))
		}
	}(time.Now())

	// Iterate over all the delivered data and inject one-by-one into the trie
	progress, stale := false, len(req.response) > 0

	for _, blob := range req.response {
		prog, hash, err := s.processNodeData(blob)
		switch err {
		case nil:
			s.numUncommitted++
			s.bytesUncommitted += len(blob)
			progress = progress || prog
		case trie.ErrNotRequested:
			unexpected++
		case trie.ErrAlreadyProcessed:
			duplicate++
		default:
			return stale, fmt.Errorf("invalid state node %s: %v", hash.TerminalString(), err)
		}
		// If the node delivered a requested item, mark the delivery non-stale
		if _, ok := req.tasks[hash]; ok {
			delete(req.tasks, hash)
			stale = false
		}
	}
	// If we're inside the critical section, reset fail counter since we progressed.
	if progress && atomic.LoadUint32(&s.syn.fsPivotFails) > 1 {
		log.Trace("Fast-sync progressed, resetting fail counter", "previous", atomic.LoadUint32(&s.syn.fsPivotFails))
		atomic.StoreUint32(&s.syn.fsPivotFails, 1) // Don't ever reset to 0, as that will unlock the pivot block
	}

	// Put unfulfilled tasks back into the retry queue
	npeers := s.syn.peers.Len()
	for hash, task := range req.tasks {
		// If the node did deliver something, missing items may be due to a protocol
		// limit or a previous timeout + delayed delivery. Both cases should permit
		// the node to retry the missing items (to avoid single-peer stalls).
		if len(req.response) > 0 || req.timedOut() {
			delete(task.attempts, req.peer.id)
		}
		// If we've requested the node too many times already, it may be a malicious
		// sync where nobody has the right data. Abort.
		if len(task.attempts) >= npeers {
			return stale, fmt.Errorf("state node %s failed with all peers (%d tries, %d peers)", hash.TerminalString(), len(task.attempts), npeers)
		}
		// Missing item, place into the retry queue.
		s.tasks[hash] = task
	}
	return stale, nil
}

// processNodeData tries to inject a trie node data blob delivered from a remote
// peer into the state trie, returning whether anything useful was written or any
// error occurred.
func (s *stateSync) processNodeData(blob []byte) (bool, common.Hash, error) {
	res := trie.SyncResult{Data: blob}
	s.keccak.Reset()
	s.keccak.Write(blob)
	s.keccak.Sum(res.Hash[:0])
	committed, _, err := s.sched.Process([]trie.SyncResult{res})
	return committed, res.Hash, err
}

// updateStats bumps the various state sync progress counters and displays a log
// message for the user to see.
func (s *stateSync) updateStats(written, duplicate, unexpected int, duration time.Duration) {
	s.syn.syncStatsLock.Lock()
	defer s.syn.syncStatsLock.Unlock()

	s.syn.syncStatsState.pending = uint64(s.sched.Pending())
	s.syn.syncStatsState.processed += uint64(written)
	s.syn.syncStatsState.duplicate += uint64(duplicate)
	s.syn.syncStatsState.unexpected += uint64(unexpected)

	if written > 0 || duplicate > 0 || unexpected > 0 {
		log.Info("Imported new state entries", "count", written, "elapsed", common.PrettyDuration(duration), "processed", s.syn.syncStatsState.processed, "pending", s.syn.syncStatsState.pending, "retry", len(s.tasks), "duplicate", s.syn.syncStatsState.duplicate, "unexpected", s.syn.syncStatsState.unexpected)
	}
}
