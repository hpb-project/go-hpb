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

package txpool

import (
	"fmt"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/event/sub"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	evictionInterval     = time.Minute     // Time interval to check for evictable transactions
	statsReportInterval  = 5 * time.Second // Time interval to report transaction pool stats
	chanHeadBuffer       = 10
	maxTransactionSize   = common.StorageSize(32 * 1024)
	tmpQEvictionInterval = 3 * time.Minute // Time interval to check for evictable tmpQueue transactions
)

var INSTANCE = atomic.Value{}
var STOPPED = atomic.Value{}

// blockChain provides the state of blockchain and current gas limit to do
// some pre checks in tx pool.
type blockChain interface {
	CurrentBlock() *types.Block
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(root common.Hash) (*state.StateDB, error)

	SubscribeChainHeadEvent(ch chan<- bc.ChainHeadEvent) sub.Subscription

	SubscribeTxhahEvent(ch chan<- consensus.Txcommonhash) sub.Subscription

	PostTxstateprocessEvents(events []interface{})
}
type Txchevent struct {
	Tx *types.Transaction
}
type TxPool struct {
	wg     sync.WaitGroup
	stopCh chan struct{}

	//TODO remove
	chain blockChain
	//TODO uddate the new event system
	chainHeadSub sub.Subscription
	chainHeadCh  chan bc.ChainHeadEvent

	txhashSub sub.Subscription
	txhashCh  chan consensus.Txcommonhash
	txFeed    sub.Feed
	scope     sub.SubscriptionScope

	txPreTrigger *event.Trigger
	//Txchevent *event.SyncEvent

	signer            types.Signer
	mu                sync.RWMutex
	muforstateprocess sync.RWMutex

	config        config.TxPoolConfiguration
	currentState  *state.StateDB      // Current state in the blockchain head
	pendingState  *state.ManagedState // Pending state tracking virtual nonces
	currentMaxGas *big.Int            // Current gas limit for transaction caps
	gasPrice      *big.Int

	pending                 map[common.Address]*txList         // All currently processable transactions
	queue                   map[common.Address]*txList         // Queued but non-processable transactions
	beats                   map[common.Address]time.Time       // Last heartbeat from each known account
	all                     map[common.Hash]*types.Transaction // All transactions to allow lookups
	tmpqueue                map[common.Hash]*types.Transaction // delete transactions to tmpqueue
	allforstateprocess      map[common.Hash]*types.Transaction // All transactions to allow lookups
	tmpqueueforstateprocess map[common.Hash]*types.Transaction // delete transactions to tmpqueue
	tmpbeats                map[common.Hash]time.Time          // Last heartbeat from each known tmpqueue account
}

const (
	TxpoolEventtype event.EventType = 0x01
)

//Create the transaction pool and start main process loop.
func NewTxPool(config config.TxPoolConfiguration, chainConfig *config.ChainConfig, blockChain blockChain) *TxPool {
	if INSTANCE.Load() != nil {
		return INSTANCE.Load().(*TxPool)
	}
	//2.Create the transaction pool with its initial settings
	pool := &TxPool{
		config:                  config,
		pending:                 make(map[common.Address]*txList),
		queue:                   make(map[common.Address]*txList),
		beats:                   make(map[common.Address]time.Time),
		all:                     make(map[common.Hash]*types.Transaction),
		gasPrice:                new(big.Int).SetUint64(config.PriceLimit),
		chain:                   blockChain,
		signer:                  types.NewBoeSigner(chainConfig.ChainId),
		chainHeadCh:             make(chan bc.ChainHeadEvent, chanHeadBuffer),
		txhashCh:                make(chan consensus.Txcommonhash, 1),
		stopCh:                  make(chan struct{}),
		tmpbeats:                make(map[common.Hash]time.Time),
		tmpqueue:                make(map[common.Hash]*types.Transaction),
		allforstateprocess:      make(map[common.Hash]*types.Transaction),
		tmpqueueforstateprocess: make(map[common.Hash]*types.Transaction),
	}
	INSTANCE.Store(pool)
	return pool
}
func (pool *TxPool) Start() {
	pool.reset(nil, pool.chain.CurrentBlock().Header())

	//3.Subscribe ChainHeadEvent //TODO update the new event system
	/*chainHeadReceiver := event.RegisterReceiver("tx_pool_chain_head_subscriber",
	func(payload interface{}) {
		switch msg := payload.(type) {
		case event.ChainHeadEvent:
			log.Trace("TxPool get ChainHeadEvent %s", msg.Message.String())
			pool.chainHeadCh <- msg
			//default:
			//	log.Warn("TxPool get Unknown msg")
		}
	})*/
	//TODO update the new evnt system
	//event.Subscribe(chainHeadReceiver, event.ChainHeadTopic)
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)
	//pool.Txchevent = event.NewEvent()
	pool.txhashSub = pool.chain.SubscribeTxhahEvent(pool.txhashCh)

	//4.Register Publish TxPre publisher
	pool.txPreTrigger = event.RegisterTrigger("tx_pool_tx_pre_publisher")

	//5.start main process loop
	pool.wg.Add(1)
	go pool.loop()
}

func GetTxPool() *TxPool {
	if INSTANCE.Load() != nil {
		return INSTANCE.Load().(*TxPool)
	}
	log.Warn("TxPool is nil, please init tx pool first.")
	return nil
}

//Stop the transaction pool.
func (pool *TxPool) Stop() {
	if STOPPED.Load() == nil {
		pool.txhashSub.Unsubscribe()
		//1.stop main process loop
		pool.stopCh <- struct{}{}
		//2.wait quit
		pool.wg.Wait()
		STOPPED.Store(true)
	}
}

//Main process loop.
func (pool *TxPool) loop() {
	defer pool.wg.Done()

	// Start the stats reporting and transaction eviction tickers
	var prevPending, prevQueued int

	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	evictTmpQueue := time.NewTicker(tmpQEvictionInterval)
	defer evictTmpQueue.Stop()

	//evictCopytxpool := time.NewTicker(time.Duration(config.GetHpbConfigInstance().Prometheus.Period-1)*time.Second)
	//defer evictCopytxpool.Stop()

	// Track the previous head headers for transaction reorgs
	head := pool.chain.CurrentBlock()

	// Keep waiting for and reacting to the various events
	for {
		select {
		//case <-evictCopytxpool.C:
		//pool.CopyAllandTempQueue()

		case txhash := <-pool.txhashCh:
			var txhashtemp common.Hash
			copy(txhashtemp[:], txhash[:])
			tx := pool.GetTxByHash(txhashtemp)
			//tx := pool.GetTxByHashforstateprocess(txhashtemp)

			events := make([]interface{}, 0, 1)
			tempfromaddr := new(consensus.Txfromaddr)

			if tx == nil {
				copy(tempfromaddr[:], consensus.Zeroaddr[:])
			} else {
				msg, err := tx.AsMessage(types.MakeSigner(&config.GetHpbConfigInstance().BlockChain))
				if err != nil {
					copy(tempfromaddr[:], consensus.Zeroaddr[:])
				} else {
					tempaddr := msg.From()
					copy(tempfromaddr[:], tempaddr[:])
					//log.Error("22222222222222222222222222222222222", "from txpool", tempfromaddr)
				}
			}
			//log.Error("3333333333333333333333333333333333333333", "from txpool", tempfromaddr)
			events = append(events, *tempfromaddr)
			pool.chain.PostTxstateprocessEvents(events)

		// Handle ChainHeadEvent
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.mu.Lock()
				//before := time.Now()
				pool.reset(head.Header(), ev.Block.Header())
				//fuhy
				//log.Error("aaaaaaaaaaaaaaaaaa txpool deal with txs from block spend time", "block number", ev.Block.Number(),"txs", len(ev.Block.Transactions()), "value", time.Now().Sub(before))
				head = ev.Block

				pool.mu.Unlock()
			}
			// Handle stats reporting ticks
		case <-report.C:
			//pool.mu.RLock()
			pending, queued := pool.Stats()
			//pool.mu.RUnlock()

			if pending != prevPending || queued != prevQueued {
				log.Debug("Transaction pool status report", "pending", pending, "queued", queued)
				prevPending, prevQueued = pending, queued
			}
			// Handle inactive account transaction eviction
		case <-evict.C:
			pool.mu.Lock()
			for addr := range pool.queue {
				// Any old enough should be removed
				if false { //time.Since(pool.beats[addr]) > pool.config.Lifetime {
					for _, tx := range pool.queue[addr].Flatten() {
						pool.removeTx(tx.Hash())
					}
				}
			}
			pool.mu.Unlock()
			//stop signal
		case <-evictTmpQueue.C: // time removed tmpTx
			pool.mu.Lock()
			// Any old enough should be removed
			for txTmphash, tmpBeatsV := range pool.tmpbeats {
				//cancel delete txs
				if time.Since(tmpBeatsV) > pool.config.Lifetime {
					delete(pool.tmpqueue, txTmphash)
					delete(pool.tmpbeats, txTmphash)
					//log.Info("delete(pool.tmpqueue)","txTmphash",txTmphash,"tmpBeatsV",tmpBeatsV,"tmphash value time",time.Since(pool.tmpbeats[txTmphash]),"cmptime",pool.config.Lifetime)
				}
			}
			pool.mu.Unlock()
			//stop signal
		case <-pool.stopCh:
			return
		}
	}
}

// reset retrieves the current state of the blockchain and ensures the content
// of the transaction pool is valid with regard to the chain state.
func (pool *TxPool) reset(oldHead, newHead *types.Header) {
	// If we're reorging an old state, reinject all dropped transactions
	var reinject types.Transactions

	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		// If the reorg is too deep, avoid doing it (will happen during fast sync)
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()

		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Warn("Skipping deep transaction reorg", "depth", depth)
		} else {
			// Reorg seems shallow enough to pull in all transactions into memory
			var discarded, included types.Transactions

			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64())
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
			)
			for rem.NumberU64() > add.NumberU64() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
			}
			for add.NumberU64() > rem.NumberU64() {
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			for rem.Hash() != add.Hash() {
				discarded = append(discarded, rem.Transactions()...)
				if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
					log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
					return
				}
				included = append(included, add.Transactions()...)
				if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
					log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
					return
				}
			}
			reinject = types.TxDifference(discarded, included)
		}
	}
	// Initialize the internal state to the current head
	if newHead == nil {
		newHead = pool.chain.CurrentBlock().Header() // Special case during testing
	}
	// Set new statedb
	statedb, err := pool.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}
	pool.currentState = statedb
	pool.pendingState = state.ManageState(statedb)
	pool.currentMaxGas = newHead.GasLimit

	// Inject any transactions discarded due to reorgs
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	pool.addTxsLocked(reinject)

	// validate the pool of pending transactions, this will remove
	// any transactions that have been included in the block or
	// have been invalidated because of another transaction
	pool.demoteUnexecutables()

	// Update all accounts to the latest known pending nonce
	for addr, list := range pool.pending {
		txs := list.Flatten() // Heavy but will be cached and is needed by the miner anyway
		pool.pendingState.SetNonce(addr, txs[len(txs)-1].Nonce()+1)
	}
	// Check the queue and move transactions over to the pending if possible
	// or remove those that have become invalid
	pool.promoteExecutables(nil)
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *TxPool) validateTxpart1(tx *types.Transaction) error {
	// Heuristic limit, reject transactions over 32KB to prevent DOS attacks
	if tx.Size() > maxTransactionSize {
		log.Trace("ErrOversizedData maxTransactionSize", "ErrOversizedData", ErrOversizedData)
		return ErrOversizedData
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur if you create a transaction using the RPC.
	if tx.Value().Sign() < 0 {
		log.Trace("ErrNegativeValue", "ErrNegativeValue", ErrNegativeValue)
		return ErrNegativeValue
	}

	// Call BOE recover sender.
	_, err := types.Sender(pool.signer, tx)
	if err != nil {
		log.Trace("ErrInvalidSender", "ErrInvalidSender", ErrInvalidSender)
		return ErrInvalidSender
	}

	intrGas := types.IntrinsicGas(tx.Data(), tx.To() == nil)
	if tx.Gas().Cmp(intrGas) < 0 {
		log.Trace("ErrIntrinsicGas", "ErrIntrinsicGas", ErrIntrinsicGas)
		return ErrIntrinsicGas
	}
	return nil
}

func (pool *TxPool) validateTxpart2(tx *types.Transaction) error {

	// Ensure the transaction doesn't exceed the current block limit gas.
	if pool.currentMaxGas.Cmp(tx.Gas()) < 0 {
		log.Trace("ErrGasLimit", "ErrGasLimit", ErrGasLimit)
		return ErrGasLimit
	}
	// Call BOE recover sender.
	from, err := types.Sender(pool.signer, tx)
	if err != nil {
		log.Trace("ErrInvalidSender", "ErrInvalidSender", ErrInvalidSender)
		return ErrInvalidSender
	}
	// Check gasPrice.
	if pool.gasPrice.Cmp(tx.GasPrice()) > 0 {
		log.Trace("ErrUnderpriced", "ErrUnderpriced", ErrUnderpriced)
		return ErrUnderpriced
	}
	// Ensure the transaction adheres to nonce ordering
	if pool.currentState.GetNonce(from) > tx.Nonce() {
		log.Trace("ErrNonceTooLow", "tx.Nonce()", tx.Nonce())
		return ErrNonceTooLow
	}
	// Transactor should have enough funds to cover the costs
	// cost == V + GP * GL
	if pool.currentState.GetBalance(from).Cmp(tx.Cost()) < 0 {
		log.Trace("ErrInsufficientFunds", "ErrInsufficientFunds", ErrInsufficientFunds)
		return ErrInsufficientFunds
	}
	return nil
}

// addTxs attempts to queue a batch of transactions if they are valid.
func (pool *TxPool) AddTxs(txs []*types.Transaction) error {
	for _, tx := range txs {
		hash := tx.Hash()
		// If the transaction fails basic validation, discard it
		if err := pool.validateTxpart1(tx); err != nil {
			log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
			return err
		}

		//pool.mu.Lock()
		//if pool.all[hash] != nil {
		//	log.Trace("Discarding already known transaction", "hash", hash)
		//	return fmt.Errorf("known transaction: %x", hash)
		//}
		//pool.mu.Unlock()
		//
		//tx.AsMessage(types.MakeSigner(&config.GetHpbConfigInstance().BlockChain))
	}

	//concurrent validate tx before pool's lock.
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, tx := range txs {
		// If the transaction fails basic validation, discard it
		hash := tx.Hash()
		if pool.all[hash] != nil {
			log.Trace("Discarding already known transaction", "hash", hash)
			return fmt.Errorf("known transaction: %x", hash)
		}

		//tx.AsMessage(types.MakeSigner(&config.GetHpbConfigInstance().BlockChain))

		if err := pool.validateTxpart2(tx); err != nil {
			log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
			return err
		}
	}

	return pool.addTxsLocked(txs)
}

// AddTx attempts to queue a transactions if valid.
func (pool *TxPool) AddTx(tx *types.Transaction) error {

	hash := tx.Hash()
	if err := pool.validateTxpart1(tx); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		return err
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.all[hash] != nil {
		log.Trace("Discarding already known transaction", "hash", hash)
		return fmt.Errorf("known transaction: %x", hash)
	}

	//tx.AsMessage(types.MakeSigner(&config.GetHpbConfigInstance().BlockChain))

	// If the transaction fails basic validation, discard it
	if err := pool.validateTxpart2(tx); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		return err
	}

	return pool.addTxLocked(tx)
}

// addTxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
func (pool *TxPool) addTxsLocked(txs []*types.Transaction) error {
	// Add the batch of transaction, tracking the accepted ones

	dirty := make(map[common.Address]struct{})
	for _, tx := range txs {
		if replace, err := pool.add(tx); err == nil {
			if !replace {
				from, _ := types.Sender(pool.signer, tx) // already validated
				dirty[from] = struct{}{}
			}
		}

	}

	// Only reprocess the internal state if something was actually added
	if len(dirty) > 0 {

		addrs := make([]common.Address, 0, len(dirty))
		for addr := range dirty {
			addrs = append(addrs, addr)
		}
		pool.promoteExecutables(addrs)

	}

	return nil
}

// addTx enqueues a single transaction into the pool if it is valid.
func (pool *TxPool) addTxLocked(tx *types.Transaction) error {
	// Try to inject the transaction and update any state
	replace, err := pool.add(tx)
	if err != nil {
		return err
	}
	// If we added a new transaction, run promotion checks and return
	if !replace {
		from, _ := types.Sender(pool.signer, tx) // already validated
		pool.promoteExecutables([]common.Address{from})
	}
	return nil
}

// add validates a transaction and inserts it into the non-executable queue for
// later pending promotion and execution. If the transaction is a replacement for
// an already pending or queued one, it overwrites the previous and returns this
// so outer code doesn't uselessly call promote.
//
// If a newly added transaction is marked as local, its sending account will be
// whitelisted, preventing any associated transaction from being dropped out of
// the pool due to pricing constraints.
func (pool *TxPool) add(tx *types.Transaction) (bool, error) {
	// If the transaction is already known, discard it
	hash := tx.Hash()
	from, _ := types.Sender(pool.signer, tx) // already validated

	// If the transaction pool is full, reject
	if uint64(len(pool.all)) >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		log.Warn("TxPool is full, reject tx", "current size", len(pool.all),
			"max size", pool.config.GlobalSlots+pool.config.GlobalQueue, "hash", hash, "from", from, "to", tx.To())
		return false, ErrTxPoolFull
	}

	// If the transaction is replacing an already pending one, do directly
	if list := pool.pending[from]; list != nil && list.Overlaps(tx) {

		// Nonce already pending, check if required price bump is met
		inserted, old := list.Add(tx, pool.config.PriceBump)
		if !inserted {
			return false, ErrReplaceUnderpriced
		}
		// New transaction is better, replace old one
		if old != nil {
			delete(pool.all, old.Hash())
		}
		pool.all[tx.Hash()] = tx
		pool.tmpqueue[tx.Hash()] = tx

		log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())

		// We've directly injected a replacement transaction, notify subsystems
		//TODO why inject event here
		//event.FireEvent(&event.Event{Trigger: pool.txPreTrigger, Payload: event.TxPreEvent{tx}, Topic: event.TxPreTopic})

		return old != nil, nil
	}
	// New transaction isn't replacing a pending one, push into queue
	replace, err := pool.enqueueTx(hash, tx)
	if err != nil {
		return false, err
	}
	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To())
	return replace, nil
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) enqueueTx(hash common.Hash, tx *types.Transaction) (bool, error) {
	// Try to insert the transaction into the future queue
	from, _ := types.Sender(pool.signer, tx) // already validated
	if pool.queue[from] == nil {
		pool.queue[from] = newTxList(false)
	}
	inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		return false, ErrReplaceUnderpriced
	}
	// Discard any previous transaction and mark this
	if old != nil {
		delete(pool.all, old.Hash())
	}
	pool.all[hash] = tx
	return old != nil, nil
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *TxPool) promoteExecutables(accounts []common.Address) {

	// Gather all the accounts potentially needing updates
	if accounts == nil {
		accounts = make([]common.Address, 0, len(pool.queue))
		for addr := range pool.queue {
			accounts = append(accounts, addr)
		}
	}

	// Iterate over all accounts and promote any executable transactions
	for _, addr := range accounts {
		list := pool.queue[addr]

		if list == nil {

			continue // Just in case someone calls with a non existing account
		}

		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(pool.currentState.GetNonce(addr)) {
			hash := tx.Hash()
			log.Trace("Removed old queued transaction", "hash", hash)
			delete(pool.all, hash)
		}

		// Drop all transactions that are too costly (low balance or out of gas)
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable queued transaction", "hash", hash)
			delete(pool.all, hash)
		}

		// Gather all executable transactions and promote them
		for _, tx := range list.Ready(pool.pendingState.GetNonce(addr)) {
			hash := tx.Hash()
			log.Trace("Promoting queued transaction", "hash", hash, "pool.pendingState.GetNonce(addr)", pool.pendingState.GetNonce(addr))
			pool.promoteTx(addr, hash, tx)

			// Delete a single queue transaction
			if list != nil {
				list.Remove(tx)
			}
		}

		// Drop all transactions over the allowed limit
		for _, tx := range list.Cap(int(pool.config.AccountQueue)) {
			hash := tx.Hash()
			delete(pool.all, hash)
			log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
		}

		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			log.Trace("promoteExecutables list.Empty()")
			delete(pool.queue, addr)
		}
	}

	pool.keepFit()

}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *TxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	for addr, list := range pool.pending {
		if pool.currentState == nil {
		}
		nonce := pool.currentState.GetNonce(addr)
		// Drop all transactions that are deemed too old (low nonce)
		for _, tx := range list.Forward(nonce) {
			hash := tx.Hash()
			log.Trace("Removed old pending transaction", "hash", hash)
			delete(pool.all, hash)
		}
		// Drop all transactions that are too costly (low balance or out of gas), and queue any invalids back for later
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable pending transaction", "hash", hash)
			delete(pool.all, hash)
		}
		for _, tx := range invalids {
			hash := tx.Hash()
			log.Trace("Demoting pending transaction", "hash", hash)
			pool.enqueueTx(hash, tx)
		}
		// If there's a gap in front, warn (should never happen) and postpone all transactions
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			for _, tx := range list.Cap(0) {
				hash := tx.Hash()
				log.Trace("Demoting invalidated transaction", "hash", hash)
				pool.enqueueTx(hash, tx)
			}
		}
		// Delete the entire queue entry if it became empty.
		if list.Empty() {
			delete(pool.pending, addr)
			delete(pool.beats, addr)
		}
	}
}

// promoteTx adds a transaction to the pending (processable) list of transactions.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) {
	// Try to insert the transaction into the pending queue
	if pool.pending[addr] == nil {
		pool.pending[addr] = newTxList(true)
	}
	list := pool.pending[addr]

	inserted, old := list.Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		delete(pool.all, hash)
		return
	}
	// Otherwise discard any previous transaction and mark this
	if old != nil {
		delete(pool.all, old.Hash())
	}
	// Failsafe to work around direct pending inserts (tests)
	if pool.all[hash] == nil {
		pool.all[hash] = tx
	}
	// pending transactions inserts tmpqueue
	if pool.tmpqueue[hash] == nil {
		pool.tmpqueue[hash] = tx
	}
	pool.tmpbeats[hash] = time.Now()

	// Set the potentially new pending nonce and notify any subsystems of the new tx
	pool.beats[addr] = time.Now()
	pool.pendingState.SetNonce(addr, tx.Nonce()+1)
	//TODO update the new event system
	//event.FireEvent(&event.Event{Trigger: pool.txPreTrigger, Payload: event.TxPreEvent{tx}, Topic: event.TxPreTopic})
	//TODO old event  system
	//go pool.txFeed.Send(bc.TxPreEvent{tx})
	pool.txFeed.Send(bc.TxPreEvent{tx})
	log.Trace("send txpre event-------", "tx.once", tx.Nonce(), "acc-addr", addr, "hash", hash)
}

//If the pending limit is overflown, start equalizing allowances
// If we've queued more transactions than the hard limit, drop oldest ones
func (pool *TxPool) keepFitSend() {
	// If the pending limit is overflown, start equalizing allowances
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len())
	}
	if pending > pool.config.GlobalSlots {
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New()
		for addr, list := range pool.pending {
			// Only evict transactions from high rollers
			if uint64(list.Len()) > pool.config.AccountSlots {
				spammers.Push(addr, float32(list.Len()))

			}
		}
		// Gradually drop transactions from offenders
		var offenders []common.Address
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				threshold := pool.pending[offender.(common.Address)].Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
					for i := 0; i < len(offenders)-1; i++ {
						list := pool.pending[offenders[i]]
						for _, tx := range list.Cap(list.Len() - 1) {
							// Drop the transaction from the global pools too
							hash := tx.Hash()
							delete(pool.all, hash)

							// Update the account nonce to the dropped transaction
							//if nonce := tx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
							//	pool.pendingState.SetNonce(offenders[i], nonce)
							//}
							log.Trace("Removed fairness-exceeding pending keepFitsend transaction ", "tx.Nonce()", tx.Nonce(), "hash", hash)
						}
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
				for _, addr := range offenders {
					list := pool.pending[addr]
					for _, tx := range list.Cap(list.Len() - 1) {
						// Drop the transaction from the global pools too
						hash := tx.Hash()
						delete(pool.all, hash)

						// Update the account nonce to the dropped transaction
						//if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
						//	pool.pendingState.SetNonce(addr, nonce)
						//}
						log.Trace("Removed fairness-exceeding keepFitsned pending transaction", "tx.Nonce()", tx.Nonce(), "hash", hash)
					}
					pending--
				}
			}
		}
	}
	// If we've queued more transactions than the hard limit, drop oldest ones
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		addresses := make(addresssByHeartbeat, 0, len(pool.queue))
		for addr := range pool.queue {
			addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
		}
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			addr := addresses[len(addresses)-1]
			list := pool.queue[addr.address]

			addresses = addresses[:len(addresses)-1]

			// Drop all transactions if they are less than the overflow
			if size := uint64(list.Len()); size <= drop {
				for _, tx := range list.Flatten() {
					pool.removeTx(tx.Hash())
					log.Trace("Removed fairness-exceeding Queue transaction", "hash", tx.Hash())
				}
				drop -= size
				continue
			}
			// Otherwise drop only last few transactions
			txs := list.Flatten()
			for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
				pool.removeTx(txs[i].Hash())
				log.Trace("Removed fairness-exceeding Queue transaction", "hash", txs[i].Hash())
				drop--
			}
		}
	}
}
func (pool *TxPool) keepFit() {
	// If the pending limit is overflown, start equalizing allowances
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len())
	}
	if pending > pool.config.GlobalSlots {
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New()
		for addr, list := range pool.pending {
			// Only evict transactions from high rollers
			if uint64(list.Len()) > pool.config.AccountSlots {
				spammers.Push(addr, float32(list.Len()))

			}
		}
		// Gradually drop transactions from offenders
		var offenders []common.Address
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				threshold := pool.pending[offender.(common.Address)].Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
					for i := 0; i < len(offenders)-1; i++ {
						list := pool.pending[offenders[i]]
						for _, tx := range list.Cap(list.Len() - 1) {
							// Drop the transaction from the global pools too
							hash := tx.Hash()
							delete(pool.all, hash)

							// Update the account nonce to the dropped transaction
							if nonce := tx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
								pool.pendingState.SetNonce(offenders[i], nonce)
							}
							log.Trace("Removed fairness-exceeding pending transaction", "tx.Nonce()", tx.Nonce(), "hash", hash)
						}
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
				for _, addr := range offenders {
					list := pool.pending[addr]
					for _, tx := range list.Cap(list.Len() - 1) {
						// Drop the transaction from the global pools too
						hash := tx.Hash()
						delete(pool.all, hash)

						// Update the account nonce to the dropped transaction
						if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
							pool.pendingState.SetNonce(addr, nonce)
						}
						log.Trace("Removed fairness-exceeding pending transaction", "tx.Nonce()", tx.Nonce(), "hash", hash)
					}
					pending--
				}
			}
		}
	}
	// If we've queued more transactions than the hard limit, drop oldest ones
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len())
	}
	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		addresses := make(addresssByHeartbeat, 0, len(pool.queue))
		for addr := range pool.queue {
			addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
		}
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			addr := addresses[len(addresses)-1]
			list := pool.queue[addr.address]

			addresses = addresses[:len(addresses)-1]

			// Drop all transactions if they are less than the overflow
			if size := uint64(list.Len()); size <= drop {
				for _, tx := range list.Flatten() {
					pool.removeTx(tx.Hash())
					log.Trace("Removed fairness-exceeding Queue transaction", "hash", tx.Hash())
				}
				drop -= size
				continue
			}
			// Otherwise drop only last few transactions
			txs := list.Flatten()
			for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
				pool.removeTx(txs[i].Hash())
				log.Trace("Removed fairness-exceeding Queue transaction", "hash", txs[i].Hash())
				drop--
			}
		}
	}
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
func (pool *TxPool) removeTx(hash common.Hash) {
	// Fetch the transaction we wish to delete
	tx, ok := pool.all[hash]
	if !ok {
		return
	}
	addr, _ := types.Sender(pool.signer, tx) // already validated during insertion

	// Remove it from the list of known transactions
	delete(pool.all, hash)

	// Remove the transaction from the pending lists and reset the account nonce
	if pending := pool.pending[addr]; pending != nil {
		if removed, invalids := pending.Remove(tx); removed {
			// If no more transactions are left, remove the list
			if pending.Empty() {
				delete(pool.pending, addr)
				delete(pool.beats, addr)
			}
			for _, tx := range invalids {
				pool.enqueueTx(tx.Hash(), tx)
			}
			// Update the account nonce if needed
			if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
				pool.pendingState.SetNonce(addr, nonce)
			}
			return
		}
	}
	// Transaction is in the future queue
	if future := pool.queue[addr]; future != nil {
		future.Remove(tx)
		if future.Empty() {
			delete(pool.queue, addr)
		}
	}
}

// addressByHeartbeat is an account address tagged with its last activity timestamp.
type addressByHeartbeat struct {
	address   common.Address
	heartbeat time.Time
}

type addresssByHeartbeat []addressByHeartbeat

func (a addresssByHeartbeat) Len() int           { return len(a) }
func (a addresssByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addresssByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

//For RPC

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len()
	}
	return pending, queued
}

// Get returns a transaction if it is contained in the pool
// and nil otherwise.
func (pool *TxPool) GetTxByHash(hash common.Hash) *types.Transaction {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	tx, ok := pool.all[hash]
	if !ok {
		tmptx, okflag := pool.tmpqueue[hash]
		if !okflag {
			log.Trace("not Finding already known tmptx transaction", "hash", hash)
			return nil
		}
		//log.Info("-----GetTxByHash","tmpqueue_hash",hash,"tmptx=",tmptx)
		return tmptx
	}
	return tx

}

func (pool *TxPool) GetTxByHashforstateprocess(hash common.Hash) *types.Transaction {
	pool.muforstateprocess.RLock()
	defer pool.muforstateprocess.RUnlock()
	tx, ok := pool.allforstateprocess[hash]
	if !ok {
		tmptx, okflag := pool.tmpqueueforstateprocess[hash]
		if !okflag {
			log.Trace("not Finding already known tmptx transaction", "hash", hash)
			return nil
		}
		//log.Info("-----GetTxByHash","tmpqueue_hash",hash,"tmptx=",tmptx)
		return tmptx
	}
	return tx

}

func (pool *TxPool) CopyAllandTempQueue() {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	pool.muforstateprocess.Lock()
	defer pool.muforstateprocess.Unlock()

	//pool.allforstateprocess = pool.all
	//pool.tmpqueueforstateprocess = pool.tmpqueue

	pool.allforstateprocess = make(map[common.Hash]*types.Transaction)
	pool.tmpqueueforstateprocess = make(map[common.Hash]*types.Transaction)

	for k, v := range pool.all {
		pool.allforstateprocess[k] = v
	}

	for k, v := range pool.tmpqueue {
		pool.tmpqueueforstateprocess[k] = v
	}
}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) Pending() (map[common.Address]types.Transactions, error) {
	//fuhy
	//pool.mu.Lock()
	//defer pool.mu.Unlock()
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	return pending, nil
}

// State returns the virtual managed state of the transaction pool.
func (pool *TxPool) State() *state.ManagedState {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.pendingState
}

func (pool *TxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pending := make(map[common.Address]types.Transactions)
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten()
	}
	queued := make(map[common.Address]types.Transactions)
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten()
	}
	return pending, queued
}

func (pool *TxPool) SubscribeTxPreEvent(ch chan<- bc.TxPreEvent) sub.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// SetGasPrice updates the minimum price required by the transaction pool for a
// new transaction
func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.gasPrice = price
	log.Info("Transaction pool price threshold updated", "price", price)
}

// For test code.
func (pool *TxPool) lockedReset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.reset(oldHead, newHead)
}
