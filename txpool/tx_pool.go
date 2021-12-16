// Copyright 2018 The go-hpb Authors
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

package txpool

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	bc "github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/event/sub"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

var (
	evictionInterval      = time.Minute     // Time interval to check for evictable transactions
	statsReportInterval   = 5 * time.Second // Time interval to report transaction pool stats
	txSlotTransactionSize = common.StorageSize(32 * 1024)
	maxTransactionSize    = 4 * txSlotTransactionSize
	chanHeadBuffer        = 10
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
}

// TxPool contains all currently known transactions.
type TxPool struct {
	wg           sync.WaitGroup
	stopCh       chan struct{}
	chain        blockChain
	chainHeadSub sub.Subscription
	chainHeadCh  chan bc.ChainHeadEvent
	txFeed       sub.Feed
	scope        sub.SubscriptionScope
	txPreTrigger *event.Trigger
	signer       types.Signer
	config       config.TxPoolConfiguration
	gasPrice     *big.Int

	// use sync.map instead of map.
	beats    sync.Map //map[common.Address]time.Time  	   Last heartbeat from each known account
	all      sync.Map //map[common.Hash]*types.Transaction All transactions to allow lookups
	userlock sync.Map //map[common.Address]*sync.RWMutex   RWMutex for one addr, used for pending and queue
	pending  sync.Map //map[common.Address]*txList         All currently processable transactions
	queue    sync.Map //map[common.Address]*txList  	   Queued but non-processable transactions

	priced *txPricedList // All transactions sorted by price

	smu sync.RWMutex // mutex for below.

	currentState  *state.StateDB      // Current state in the blockchain head
	pendingState  *state.ManagedState // Pending state tracking virtual nonces
	currentMaxGas *big.Int            // Current gas limit for transaction caps
}

const (
	// TxpoolEventtype txpool event type.
	TxpoolEventtype event.EventType = 0x01
)

//NewTxPool Create the transaction pool and start main process loop.
func NewTxPool(config config.TxPoolConfiguration, chainConfig *config.ChainConfig, blockChain blockChain) *TxPool {
	if INSTANCE.Load() != nil {
		return INSTANCE.Load().(*TxPool)
	}
	//2.Create the transaction pool with its initial settings
	pool := &TxPool{
		config:      config,
		gasPrice:    new(big.Int).SetUint64(config.PriceLimit),
		chain:       blockChain,
		signer:      types.NewBoeSigner(chainConfig.ChainId),
		chainHeadCh: make(chan bc.ChainHeadEvent, chanHeadBuffer),
		stopCh:      make(chan struct{}),
	}

	pool.priced = newTxPricedList(&pool.all)

	INSTANCE.Store(pool)
	return pool
}

// Start start txpool.
func (pool *TxPool) Start() {
	pool.reset(nil, pool.chain.CurrentBlock().Header())
	pool.chainHeadSub = pool.chain.SubscribeChainHeadEvent(pool.chainHeadCh)

	// Register Publish TxPre publisher
	pool.txPreTrigger = event.RegisterTrigger("tx_pool_tx_pre_publisher")

	// start main process loop
	pool.wg.Add(1)
	go pool.loop()
}

// GetTxPool get txpool instance.
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
	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	// Track the previous head headers for transaction reorgs
	head := pool.chain.CurrentBlock()

	// Start the stats reporting and transaction eviction tickers
	var prevPending, prevQueued, prevStales int

	// Keep waiting for and reacting to the various events
	for {
		select {
		// Handle ChainHeadEvent
		case ev := <-pool.chainHeadCh:
			if ev.Block != nil {
				pool.smu.Lock()
				pool.reset(head.Header(), ev.Block.Header())
				head = ev.Block
				pool.smu.Unlock()
			}
		// Handle inactive account transaction eviction
		case <-evict.C:
			// Any old enough should be removed
			pool.queue.Range(func(k, v interface{}) bool {
				var tmpBeatsV time.Time
				addr := k.(common.Address)
				t, ok := pool.beats.Load(addr)
				if ok {
					tmpBeatsV = t.(time.Time)
				}
				if time.Since(tmpBeatsV) > pool.config.Lifetime {
					if lv, ok := pool.queue.Load(addr); ok {
						list := lv.(*txList)
						ul, _ := pool.userlock.Load(addr)
						userlk := ul.(*sync.RWMutex)
						userlk.Lock()
						for _, tx := range list.Flatten() {
							pool.removeTxLocked(tx.Hash())
						}
						userlk.Unlock()
					}
				}
				return true
			})

			// Handle stats reporting ticks
		case <-report.C:
			pending, queued := pool.Stats()
			stales := pool.priced.stales

			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued, "stales", stales)
				prevPending, prevQueued, prevStales = pending, queued, stales
			}

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

	//batch TxsAsynSender
	go pool.GoTxsAsynSender(reinject)

	// Inject any transactions discarded due to reorgs
	log.Debug("txpool reset Reinjecting stale transactions", "count", len(reinject))

	pool.addTxsLocked(reinject)

	// validate the pool of pending transactions, this will remove
	// any transactions that have been included in the block or
	// have been invalidated because of another transaction
	pool.demoteUnexecutables()
	// Update all accounts to the latest known pending nonce
	pool.pending.Range(func(k, v interface{}) bool {
		addr, _ := k.(common.Address)
		list, _ := v.(*txList)
		mu, _ := pool.userlock.Load(addr)
		if userl, ok := mu.(*sync.RWMutex); ok {
			userl.Lock()
			txs := list.Flatten()
			userl.Unlock()
			pool.pendingState.SetNonce(addr, txs[len(txs)-1].Nonce()+1)
		}
		return true
	})

	// Check the queue and move transactions over to the pending if possible
	// or remove those that have become invalid
	pool.promoteExecutables(nil)
}

func (pool *TxPool) softvalidateTx(tx *types.Transaction) error {
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
	from, err := types.Sender(pool.signer, tx)
	if err != nil {
		log.Error("validateTx Sender ErrInvalidSender", "ErrInvalidSender", ErrInvalidSender, "tx.hash", tx.Hash())
		return ErrInvalidSender
	}

	// Ensure the transaction doesn't exceed the current block limit gas.
	if pool.currentMaxGas.Cmp(tx.Gas()) < 0 {
		log.Trace("ErrGasLimit", "ErrGasLimit", ErrGasLimit)
		return ErrGasLimit
	}

	// Check gasPrice.
	if pool.gasPrice.Cmp(tx.GasPrice()) > 0 {
		log.Debug("tx validate", "pool gasprice", pool.gasPrice.Text(10), "tx price", tx.GasPrice().Text(10))
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
	intrGas := types.IntrinsicGas(tx.Data(), tx.To() == nil, true)
	if tx.Gas().Cmp(intrGas) < 0 {
		log.Trace("ErrIntrinsicGas", "ErrIntrinsicGas", ErrIntrinsicGas)
		return ErrIntrinsicGas
	}
	return nil
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *TxPool) validateTx(tx *types.Transaction) error {
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
	from, err := types.ASynSender(pool.signer, tx)
	if err != nil {
		log.Trace("validateTx ASynSender ErrInvalid", "ErrInvalidSender", ErrInvalidSender, "tx.hash", tx.Hash())
		from2, err := types.Sender(pool.signer, tx)

		if err != nil {
			log.Error("validateTx Sender ErrInvalidSender", "ErrInvalidSender", ErrInvalidSender, "tx.hash", tx.Hash())
			return ErrInvalidSender
		}
		copy(from[0:], from2[0:])
	}

	// Ensure the transaction doesn't exceed the current block limit gas.
	if pool.currentMaxGas.Cmp(tx.Gas()) < 0 {
		log.Trace("ErrGasLimit", "ErrGasLimit", ErrGasLimit)
		return ErrGasLimit
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
	intrGas := types.IntrinsicGas(tx.Data(), tx.To() == nil, true)
	if tx.Gas().Cmp(intrGas) < 0 {
		log.Trace("ErrIntrinsicGas", "ErrIntrinsicGas", ErrIntrinsicGas)
		return ErrIntrinsicGas
	}
	return nil
}

var (
	allCnt         = int64(0)
	pendingCnt     = int64(0)
	normalQueueLen = uint64(200000) // nornal queue/pending account number
)

// AddTxs attempts to queue a batch of transactions if they are valid.
func (pool *TxPool) AddTxs(txs []*types.Transaction) error {
	//concurrent validate tx before pool's lock.
	if len(txs) == 0 {
		return nil
	}
	pool.smu.RLock()
	defer pool.smu.RUnlock()

	addTxs := []*types.Transaction{}
	for _, tx := range txs {
		// If the transaction fails basic validation, discard it
		if err := pool.softvalidateTx(tx); err != nil {
			log.Debug("Discarding invalid transaction", "hash", tx.Hash(), "err", err)
			continue
		}
		addTxs = append(addTxs, tx)
	}
	return pool.addTxsLocked(addTxs)
}

// AddTx attempts to queue a transactions if valid.
func (pool *TxPool) AddTx(tx *types.Transaction) error {
	hash := tx.Hash()
	if _, ok := pool.all.Load(hash); ok {
		log.Trace("Discarding already known transaction", "hash", hash)
		return fmt.Errorf("known transaction: %x", hash)
	}

	pool.smu.RLock()
	defer pool.smu.RUnlock()
	// If the transaction fails basic validation, discard it
	if err := pool.softvalidateTx(tx); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		return err
	}

	recerr := pool.addTxLocked(tx)
	if recerr != nil {
		return recerr
	}
	return nil
}

// addTxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
func (pool *TxPool) addTxsLocked(txs []*types.Transaction) error {
	// Add the batch of transaction, tracking the accepted ones
	dirty := make(map[common.Address]struct{})
	for _, tx := range txs {
		if replace, err := pool.add(tx); err == nil {

			if !replace {
				from, err := types.Sender(pool.signer, tx) // already validated
				if err != nil {
					continue
				}

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

// GoTxsAsynSender attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
func (pool *TxPool) GoTxsAsynSender(txs []*types.Transaction) error {
	for _, tx := range txs {
		types.ASynSender(pool.signer, tx)
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
		from, err := types.Sender(pool.signer, tx) // already validated
		if err != nil {
			return nil
		}
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
	hash := tx.Hash()
	from, _ := types.Sender(pool.signer, tx) // already validated

	// If the transaction pool is full, discard underpriced transactions
	if uint64(allCnt) >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		// If the new transaction is underpriced, don't accept it
		if pool.priced.Underpriced(tx) {
			log.Trace("Discarding underpriced transaction", "hash", hash, "price", tx.GasPrice())
			return false, ErrUnderpriced
		}
		// New transaction is better than our worse ones, make room for it
		drop := pool.priced.Discard(int(allCnt) - int(pool.config.GlobalSlots+pool.config.GlobalQueue-1))
		for _, tx := range drop {
			log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash(), "price", tx.GasPrice())
			pool.removeTxLocked(tx.Hash())
		}
	}

	// If the transaction is replacing an already pending one, do directly
	var ul = new(sync.RWMutex)
	ulk, _ := pool.userlock.LoadOrStore(from, ul)
	userlk := ulk.(*sync.RWMutex)
	userlk.Lock()
	defer userlk.Unlock()
	if lv, ok := pool.pending.Load(from); ok {
		if list, ok := lv.(*txList); ok && list.Overlaps(tx) {

			// Nonce already pending, check if required price bump is met
			inserted, old := list.Add(tx, pool.config.PriceBump)
			if !inserted {
				return false, ErrReplaceUnderpriced
			}
			// New transaction is better, replace old one
			if old != nil {
				pool.all.Delete(old.Hash())
				atomic.AddInt64(&allCnt, -1)
				pool.priced.Removed(allCnt)
			}
			pool.all.Store(tx.Hash(), tx)
			atomic.AddInt64(&allCnt, 1)
			pool.priced.Put(tx)

			log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())
			return old != nil, nil
		}
	}
	// New transaction isn't replacing a pending one, push into queue
	replace, err := pool.enqueueTxLocked(hash, tx)
	if err != nil {
		return false, err
	}
	if _, ok := pool.beats.Load(from); !ok {
		pool.beats.Store(from, time.Now())
	}
	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To())
	return replace, nil
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) enqueueTxLocked(hash common.Hash, tx *types.Transaction) (bool, error) {
	// Try to insert the transaction into the future queue

	from, _ := types.Sender(pool.signer, tx) // already validated

	nlist := newTxList(false)
	lv, _ := pool.queue.LoadOrStore(from, nlist)
	nlist = lv.(*txList)
	inserted, old := nlist.Add(tx, pool.config.PriceBump)

	if !inserted {
		// An older transaction was better, discard this
		return false, ErrReplaceUnderpriced
	}

	// Discard any previous transaction and mark this
	if old != nil {
		pool.all.Delete(old.Hash())
		atomic.AddInt64(&allCnt, -1)
		pool.priced.Removed(allCnt)
	}
	if _, ok := pool.all.LoadOrStore(hash, tx); !ok {
		atomic.AddInt64(&allCnt, 1)
		pool.priced.Put(tx)
	}
	return old != nil, nil
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *TxPool) promoteExecutables(accounts []common.Address) {
	// Gather all the accounts potentially needing updates
	if accounts == nil {
		accounts = make([]common.Address, 0, normalQueueLen)
		pool.queue.Range(func(k, v interface{}) bool {
			addr := k.(common.Address)
			accounts = append(accounts, addr)
			return true
		})
	}

	// Iterate over all accounts and promote any executable transactions
	pool.queue.Range(func(k, v interface{}) bool {
		addr := k.(common.Address)
		ul, _ := pool.userlock.Load(addr)
		userlk := ul.(*sync.RWMutex)
		userlk.Lock()

		if list, ok := v.(*txList); ok && list != nil {
			// Drop all transactions that are deemed too old (low nonce)
			for _, tx := range list.Forward(pool.currentState.GetNonce(addr)) {
				hash := tx.Hash()
				log.Trace("Removed old queued transaction", "hash", hash)
				pool.all.Delete(hash)
				atomic.AddInt64(&allCnt, -1)
				pool.priced.Removed(allCnt)

			}
			// Drop all transactions that are too costly (low balance or out of gas)
			drops, _ := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
			for _, tx := range drops {
				hash := tx.Hash()
				log.Trace("Removed unpayable queued transaction", "hash", hash)
				pool.all.Delete(hash)
				atomic.AddInt64(&allCnt, -1)
				pool.priced.Removed(allCnt)
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
				pool.all.Delete(hash)
				atomic.AddInt64(&allCnt, -1)
				pool.priced.Removed(allCnt)
				log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
			}

			// Delete the entire queue entry if it became empty.
			if list.Empty() {
				log.Trace("promoteExecutables list.Empty()")
				pool.queue.Delete(addr)
			}
		}
		userlk.Unlock()

		return true
	})

	pool.keepFit()
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *TxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	if pool.currentState == nil {
		return
	}

	pool.pending.Range(func(k, v interface{}) bool {
		addr := k.(common.Address)
		ul, _ := pool.userlock.Load(addr)
		userlk := ul.(*sync.RWMutex)
		userlk.Lock()
		defer userlk.Unlock()

		nonce := pool.currentState.GetNonce(addr)
		if list, ok := v.(*txList); ok && list != nil {
			// Drop all transactions that are deemed too old (low nonce)
			for _, tx := range list.Forward(nonce) {
				hash := tx.Hash()
				log.Trace("Removed old pending transaction", "hash", hash)
				pool.all.Delete(hash)
				atomic.AddInt64(&allCnt, -1)
				pool.priced.Removed(allCnt)
			}
			// Drop all transactions that are too costly (low balance or out of gas), and queue any invalids back for later
			drops, invalids := list.Filter(pool.currentState.GetBalance(addr), pool.currentMaxGas)
			for _, tx := range drops {
				hash := tx.Hash()
				log.Trace("Removed unpayable pending transaction", "hash", hash)
				pool.all.Delete(hash)
				atomic.AddInt64(&allCnt, -1)
				pool.priced.Removed(allCnt)
			}
			for _, tx := range invalids {
				hash := tx.Hash()
				log.Trace("Demoting pending transaction", "hash", hash)
				pool.enqueueTxLocked(hash, tx)
			}
			// If there's a gap in front, warn (should never happen) and postpone all transactions
			if list.Len() > 0 && list.txs.Get(nonce) == nil {
				for _, tx := range list.Cap(0) {
					hash := tx.Hash()
					log.Error("Demoting invalidated transaction", "hash", hash)
					pool.enqueueTxLocked(hash, tx)
				}
			}
			// Delete the entire queue entry if it became empty.
			if list.Empty() {
				pool.pending.Delete(addr)
				atomic.AddInt64(&pendingCnt, -1)
				pool.beats.Delete(addr)
			}
		}

		return true
	})
}

// promoteTx adds a transaction to the pending (processable) list of transactions.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) {
	// Try to insert the transaction into the pending queue
	list := newTxList(true)
	lv, exist := pool.pending.LoadOrStore(addr, list)
	if !exist {
		atomic.AddInt64(&pendingCnt, 1)
	}
	list = lv.(*txList)

	inserted, old := list.Add(tx, pool.config.PriceBump)
	if !inserted {
		// An older transaction was better, discard this
		pool.all.Delete(hash)
		atomic.AddInt64(&allCnt, -1)
		pool.priced.Removed(allCnt)
		return
	}
	// Otherwise discard any previous transaction and mark this
	if old != nil {
		pool.all.Delete(old.Hash())
		atomic.AddInt64(&allCnt, -1)
		pool.priced.Removed(allCnt)
	}
	// Failsafe to work around direct pending inserts (tests)
	_, exist = pool.all.LoadOrStore(hash, tx)
	if !exist {
		atomic.AddInt64(&allCnt, 1)
		pool.priced.Put(tx)
	}

	// Set the potentially new pending nonce and notify any subsystems of the new tx
	pool.beats.Store(addr, time.Now())
	pool.pendingState.SetNonce(addr, tx.Nonce()+1)
	go pool.txFeed.Send(bc.TxPreEvent{Tx: tx})
	log.Trace("send txpre event-------", "tx.once", tx.Nonce(), "acc-addr", addr, "hash", hash)
}

// If the pending limit is overflown, start equalizing allowances
// If we've queued more transactions than the hard limit, drop oldest ones
func (pool *TxPool) keepFit() {
	// If the pending limit is overflown, start equalizing allowances
	pending := uint64(0)
	pool.pending.Range(func(k, v interface{}) bool {
		list, _ := v.(*txList)
		pending += uint64(list.Len())
		return true
	})

	if pending > pool.config.GlobalSlots {
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New()
		pool.pending.Range(func(k, v interface{}) bool {
			addr := k.(common.Address)
			list := v.(*txList)
			if uint64(list.Len()) > pool.config.AccountSlots {
				spammers.Push(addr, float32(list.Len()))
			}
			return true
		})

		// Gradually drop transactions from offenders
		var offenders []common.Address
		for pending > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Address))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Calculate the equalization threshold for all current offenders
				lv, _ := pool.pending.Load(offender.(common.Address))
				list := lv.(*txList)
				threshold := list.Len()

				// Iteratively reduce all offenders until below limit or threshold reached
				for pending > pool.config.GlobalSlots {
					if lv2, ok := pool.pending.Load(offenders[len(offenders)-2]); ok {
						list2, ok := lv2.(*txList)
						if ok && list2.Len() <= threshold {
							break
						}
					} else {
						break
					}
					for i := 0; i < len(offenders)-1; i++ {
						ul, _ := pool.userlock.Load(offenders[i])
						userlk := ul.(*sync.RWMutex)
						userlk.Lock()
						if lv3, ok := pool.pending.Load(offenders[i]); ok {
							if list3, ok := lv3.(*txList); ok {
								for _, tx := range list3.Cap(list3.Len() - 1) {
									// Drop the transaction from the global pools too
									hash := tx.Hash()
									pool.all.Delete(hash)
									atomic.AddInt64(&allCnt, -1)
									pool.priced.Removed(allCnt)

									// Update the account nonce to the dropped transaction
									if nonce := tx.Nonce(); pool.pendingState.GetNonce(offenders[i]) > nonce {
										pool.pendingState.SetNonce(offenders[i], nonce)
									}
									log.Trace("Removed fairness-exceeding pending transaction", "tx.Nonce()", tx.Nonce(), "hash", hash)
								}
							}
						}

						userlk.Unlock()
						pending--
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if pending > pool.config.GlobalSlots && len(offenders) > 0 {
			for pending > pool.config.GlobalSlots {
				if v, ok := pool.pending.Load(offenders[len(offenders)-1]); ok {
					list, ok := v.(*txList)
					if ok && (uint64(list.Len()) <= pool.config.AccountSlots) {
						break
					}
				} else {
					break
				}

				for _, addr := range offenders {
					ul, _ := pool.userlock.Load(addr)
					userlk := ul.(*sync.RWMutex)
					userlk.Lock()
					if lv, ok := pool.pending.Load(addr); ok {
						list, ok := lv.(*txList)
						if ok && list != nil {
							for _, tx := range list.Cap(list.Len() - 1) {
								// Drop the transaction from the global pools too
								hash := tx.Hash()
								pool.all.Delete(hash)
								atomic.AddInt64(&allCnt, -1)
								pool.priced.Removed(allCnt)

								// Update the account nonce to the dropped transaction
								if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
									pool.pendingState.SetNonce(addr, nonce)
								}
								log.Trace("Removed fairness-exceeding pending transaction", "tx.Nonce()", tx.Nonce(), "hash", hash)
							}
						}
					}

					userlk.Unlock()
					pending--
				}
			}
		}
	}
	// If we've queued more transactions than the hard limit, drop oldest ones
	queued := uint64(0)
	pool.queue.Range(func(k, v interface{}) bool {
		list := v.(*txList)
		queued += uint64(list.Len())
		return true
	})

	if queued > pool.config.GlobalQueue {
		// Sort all accounts with queued transactions by heartbeat
		addresses := make(addresssByHeartbeat, 0, normalQueueLen)
		pool.queue.Range(func(k, v interface{}) bool {
			addr := k.(common.Address)
			if v, ok := pool.beats.Load(addr); ok {
				tm := v.(time.Time)
				addresses = append(addresses, addressByHeartbeat{addr, tm})
			} else {
				addresses = append(addresses, addressByHeartbeat{addr, time.Time{}})
			}
			return true
		})
		sort.Sort(addresses)

		// Drop transactions until the total is below the limit or only locals remain
		for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
			addr := addresses[len(addresses)-1]
			ul, _ := pool.userlock.Load(addr.address)
			userlk := ul.(*sync.RWMutex)
			userlk.Lock()
			if lv, ok := pool.queue.Load(addr.address); ok {
				list := lv.(*txList)

				addresses = addresses[:len(addresses)-1]

				// Drop all transactions if they are less than the overflow
				if size := uint64(list.Len()); size <= drop {
					for _, tx := range list.Flatten() {
						pool.removeTxLocked(tx.Hash())
						log.Debug("Removed fairness-exceeding Queue transaction", "hash", tx.Hash())
					}
					drop -= size
					userlk.Unlock()
					continue
				}
				// Otherwise drop only last few transactions
				txs := list.Flatten()

				for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
					pool.removeTxLocked(txs[i].Hash())
					log.Debug("Removed fairness-exceeding Queue transaction", "hash", txs[i].Hash())
					drop--
				}

			}
			userlk.Unlock()
		}
	}
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
func (pool *TxPool) removeTxLocked(hash common.Hash) {

	// Fetch the transaction we wish to delete
	v, ok := pool.all.Load(hash)
	if !ok {
		return
	}
	tx := v.(*types.Transaction)
	addr, _ := types.Sender(pool.signer, tx) // already validated during insertion

	// Remove it from the list of known transactions
	pool.all.Delete(hash)
	atomic.AddInt64(&allCnt, -1)
	pool.priced.Removed(allCnt)

	if pv, ok := pool.pending.Load(addr); ok {
		list := pv.(*txList)
		if removed, invalids := list.Remove(tx); removed {
			// If no more transactions are left, remove the list
			if list.Empty() {
				pool.pending.Delete(addr)
				atomic.AddInt64(&pendingCnt, -1)
				pool.beats.Delete(addr)
			}

			for _, tx := range invalids {
				pool.enqueueTxLocked(tx.Hash(), tx)
			}
			// Update the account nonce if needed
			if nonce := tx.Nonce(); pool.pendingState.GetNonce(addr) > nonce {
				pool.pendingState.SetNonce(addr, nonce)
			}
			return
		}
	}

	// Transaction is in the future queue
	if future, ok := pool.queue.Load(addr); ok {
		flist, _ := future.(*txList)
		flist.Remove(tx)
		if flist.Empty() {
			pool.queue.Delete(addr)
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

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) Stats() (int, int) {
	pending := 0
	queued := 0
	pool.pending.Range(func(k, v interface{}) bool {
		list := v.(*txList)
		pending += list.Len()
		return true
	})
	pool.queue.Range(func(k, v interface{}) bool {
		list := v.(*txList)
		queued += list.Len()
		return true
	})

	return pending, queued
}

// GetTxByHash Get returns a transaction if it is contained in the pool
// and nil otherwise.
func (pool *TxPool) GetTxByHash(hash common.Hash) *types.Transaction {
	v, ok := pool.all.Load(hash)
	if !ok {
		log.Trace("not Finding already known tmptx transaction", "hash", hash)
		return nil
	}
	tx := v.(*types.Transaction)
	return tx

}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) Pending() (map[common.Address]types.Transactions, error) {
	pending := make(map[common.Address]types.Transactions)
	pool.pending.Range(func(k, v interface{}) bool {
		addr := k.(common.Address)
		if lk, ok := pool.userlock.Load(addr); ok {
			mu := lk.(*sync.RWMutex)
			mu.Lock()
			defer mu.Unlock()
			list := v.(*txList)
			pending[addr] = list.Flatten()
		}
		return true
	})
	return pending, nil
}

// State returns the virtual managed state of the transaction pool.
func (pool *TxPool) State() *state.ManagedState {
	pool.smu.RLock()
	defer pool.smu.RUnlock()

	return pool.pendingState
}

// Content returns txpool pending and queue content.
func (pool *TxPool) Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	pending := make(map[common.Address]types.Transactions)
	queued := make(map[common.Address]types.Transactions)
	pool.pending.Range(func(k, v interface{}) bool {
		addr := k.(common.Address)
		if lk, ok := pool.userlock.Load(addr); ok {
			mu := lk.(*sync.RWMutex)
			mu.Lock()
			defer mu.Unlock()
			list := v.(*txList)
			pending[addr] = list.Flatten()
		}
		return true
	})
	pool.queue.Range(func(k, v interface{}) bool {
		addr := k.(common.Address)

		if lk, ok := pool.userlock.Load(addr); ok {
			mu := lk.(*sync.RWMutex)
			mu.Lock()
			defer mu.Unlock()
			list := v.(*txList)
			queued[addr] = list.Flatten()
		}
		return true
	})

	return pending, queued
}

// SubscribeTxPreEvent ...
func (pool *TxPool) SubscribeTxPreEvent(ch chan<- bc.TxPreEvent) sub.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

// SetGasPrice updates the minimum price required by the transaction pool for a
// new transaction
func (pool *TxPool) SetGasPrice(price *big.Int) {
	pool.smu.Lock()
	defer pool.smu.Unlock()

	pool.gasPrice = price
	for _, tx := range pool.priced.Cap(price) {
		pool.removeTxLocked(tx.Hash())
	}
	log.Info("Transaction pool price threshold updated", "price", price)
}

// For test code.
func (pool *TxPool) lockedReset(oldHead, newHead *types.Header) {
	pool.smu.Lock()
	defer pool.smu.Unlock()

	pool.reset(oldHead, newHead)
}

func (pool *TxPool) pendingTxList(addr common.Address) *txList {
	v, ok := pool.pending.Load(addr)
	if !ok {
		return nil
	}
	return v.(*txList)
}

func (pool *TxPool) queueTxList(addr common.Address) *txList {
	v, ok := pool.queue.Load(addr)
	if !ok {
		return nil
	}
	return v.(*txList)
}

func (pool *TxPool) pendingLen() int {
	var len int
	pool.pending.Range(func(k, v interface{}) bool {
		len++
		return true
	})
	return len
}

func (pool *TxPool) queueLen() int {
	var len int
	pool.queue.Range(func(k, v interface{}) bool {
		len++
		return true
	})
	return len
}

func (pool *TxPool) allLen() int {
	var len int
	pool.all.Range(func(k, v interface{}) bool {
		len++
		return true
	})
	return len
}
