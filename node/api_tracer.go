// Copyright 2020 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2017 The go-ethereum Authors.
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

package node

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/vmcore"
	vmcorevm "github.com/hpb-project/go-hpb/vmcore/vm"

	core "github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/common/trie"
	params "github.com/hpb-project/go-hpb/config"
	evm "github.com/hpb-project/go-hpb/evm"
	eevm "github.com/hpb-project/go-hpb/evm/vm"
	"github.com/hpb-project/go-hpb/hvm"
	vm "github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/internal/hpbapi"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/node/tracers"
)

const (
	// defaultTraceTimeout is the amount of time a single transaction can execute
	// by default before being forcefully aborted.
	defaultTraceTimeout = 5 * time.Second

	// defaultTraceReexec is the number of blocks the tracer is willing to go back
	// and reexecute to produce missing historical state necessary to run a specific
	// trace.
	defaultTraceReexec = uint64(128)
)

// TraceConfig holds extra parameters to trace functions.
type TraceConfig struct {
	*vm.LogConfig
	Tracer  *string
	Timeout *string
	Reexec  *uint64
}

// StdTraceConfig holds extra parameters to standard-json trace functions.
type StdTraceConfig struct {
	vm.LogConfig
	Reexec *uint64
	TxHash common.Hash
}

// txTraceResult is the result of a single transaction trace.
type txTraceResult struct {
	Result interface{} `json:"result,omitempty"` // Trace results produced by the tracer
	Error  string      `json:"error,omitempty"`  // Trace failure produced by the tracer
}

// blockTraceTask represents a single block trace task when an entire chain is
// being traced.
type blockTraceTask struct {
	statedb *state.StateDB   // Intermediate state prepped for tracing
	block   *types.Block     // Block to trace the transactions from
	rootref common.Hash      // Trie root reference held for this task
	results []*txTraceResult // Trace results procudes by the task
}

// blockTraceResult represets the results of tracing a single block when an entire
// chain is being traced.
type blockTraceResult struct {
	Block  hexutil.Uint64   `json:"block"`  // Block number corresponding to this trace
	Hash   common.Hash      `json:"hash"`   // Block hash corresponding to this trace
	Traces []*txTraceResult `json:"traces"` // Trace results produced by the task
}

// txTraceTask represents a single transaction trace task when an entire block
// is being traced.
type txTraceTask struct {
	statedb *state.StateDB // Intermediate state prepped for tracing
	index   int            // Transaction offset in the block
}

// TraceChain returns the structured logs created during the execution of EVM
// between two blocks (excluding start) and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceChain(ctx context.Context, start, end rpc.BlockNumber, config *TraceConfig) (*rpc.Subscription, error) {
	// Fetch the block interval that we want to trace
	var from, to *types.Block

	switch start {
	case rpc.PendingBlockNumber:
		// from = api.hpb.miner.PendingBlock()
		from = api.hpb.BlockChain().CurrentBlock()
	case rpc.LatestBlockNumber:
		from = api.hpb.BlockChain().CurrentBlock()
	default:
		from = api.hpb.BlockChain().GetBlockByNumber(uint64(start))
	}
	switch end {
	case rpc.PendingBlockNumber:
		// from = api.hpb.miner.PendingBlock()
		from = api.hpb.BlockChain().CurrentBlock()
	case rpc.LatestBlockNumber:
		to = api.hpb.BlockChain().CurrentBlock()
	default:
		to = api.hpb.BlockChain().GetBlockByNumber(uint64(end))
	}
	// Trace the chain if we've found all our blocks
	if from == nil {
		return nil, fmt.Errorf("starting block #%d not found", start)
	}
	if to == nil {
		return nil, fmt.Errorf("end block #%d not found", end)
	}
	if from.Number().Cmp(to.Number()) >= 0 {
		return nil, fmt.Errorf("end block (#%d) needs to come after start block (#%d)", end, start)
	}
	return api.traceChain(ctx, from, to, config)
}

// traceChain configures a new tracer according to the provided configuration, and
// executes all the transactions contained within. The return value will be one item
// per transaction, dependent on the requested tracer.
func (api *PrivateDebugAPI) traceChain(ctx context.Context, start, end *types.Block, config *TraceConfig) (*rpc.Subscription, error) {
	// Tracing a chain is a **long** operation, only do with subscriptions
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return &rpc.Subscription{}, rpc.ErrNotificationsUnsupported
	}
	sub := notifier.CreateSubscription()

	// Ensure we have a valid starting state before doing any work
	origin := start.NumberU64()
	database := state.NewDatabase(api.hpb.ChainDb())

	if number := start.NumberU64(); number > 0 {
		start = api.hpb.BlockChain().GetBlock(start.ParentHash(), start.NumberU64()-1)
		if start == nil {
			return nil, fmt.Errorf("parent block #%d not found", number-1)
		}
	}
	statedb, err := state.New(start.Root(), database)
	if err != nil {
		// If the starting state is missing, allow some number of blocks to be reexecuted
		reexec := defaultTraceReexec
		if config != nil && config.Reexec != nil {
			reexec = *config.Reexec
		}
		// Find the most recent block that has the state available
		for i := uint64(0); i < reexec; i++ {
			start = api.hpb.BlockChain().GetBlock(start.ParentHash(), start.NumberU64()-1)
			if start == nil {
				break
			}
			if statedb, err = state.New(start.Root(), database); err == nil {
				break
			}
		}
		// If we still don't have the state available, bail out
		if err != nil {
			switch err.(type) {
			case *trie.MissingNodeError:
				return nil, errors.New("required historical state unavailable")
			default:
				return nil, err
			}
		}
	}
	// Execute all the transaction contained within the chain concurrently for each block
	blocks := int(end.NumberU64() - origin)

	threads := runtime.NumCPU()
	if threads > blocks {
		threads = blocks
	}
	var (
		pend    = new(sync.WaitGroup)
		tasks   = make(chan *blockTraceTask, threads)
		results = make(chan *blockTraceTask, threads)
	)
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()

			// Fetch and execute the next block trace tasks
			for task := range tasks {
				signer := types.MakeSigner(api.hpb.BlockChain().Config())
				blockCtx := hvm.NewEVMContextWithoutMessage(task.block.Header(), api.hpb.BlockChain(), nil)
				// Trace all the transactions contained within
				for i, tx := range task.block.Transactions() {
					msg, _ := tx.AsMessage(signer)
					var res interface{}
					if task.block.NumberU64() >= consensus.StageNumberEvmV2 && task.block.NumberU64() < consensus.StateNumberEvmRevert {
						res, err = api.traceTx_evm(ctx, msg, task.statedb, config, task.block.Header())
					} else {
						res, err = api.traceTx(ctx, msg, blockCtx, task.statedb, config, task.block.Header())
					}
					if err != nil {
						task.results[i] = &txTraceResult{Error: err.Error()}
						log.Warn("Tracing failed", "hash", tx.Hash(), "block", task.block.NumberU64(), "err", err)
						break
					}
					task.statedb.Finalise(false)
					task.results[i] = &txTraceResult{Result: res}
				}
				// Stream the result back to the user or abort on teardown
				select {
				case results <- task:
				case <-notifier.Closed():
					return
				}
			}
		}()
	}
	// Start a goroutine to feed all the blocks into the tracers
	begin := time.Now()

	go func() {
		var (
			logged time.Time
			number uint64
			traced uint64
			failed error
			proot  common.Hash
		)
		// Ensure everything is properly cleaned up on any exit path
		defer func() {
			close(tasks)
			pend.Wait()

			switch {
			case failed != nil:
				log.Warn("Chain tracing failed", "start", start.NumberU64(), "end", end.NumberU64(), "transactions", traced, "elapsed", time.Since(begin), "err", failed)
			case number < end.NumberU64():
				log.Warn("Chain tracing aborted", "start", start.NumberU64(), "end", end.NumberU64(), "abort", number, "transactions", traced, "elapsed", time.Since(begin))
			default:
				log.Info("Chain tracing finished", "start", start.NumberU64(), "end", end.NumberU64(), "transactions", traced, "elapsed", time.Since(begin))
			}
			close(results)
		}()
		// Feed all the blocks both into the tracer, as well as fast process concurrently
		for number = start.NumberU64() + 1; number <= end.NumberU64(); number++ {
			// Stop tracing if interruption was requested
			select {
			case <-notifier.Closed():
				return
			default:
			}
			// Print progress logs if long enough time elapsed
			if time.Since(logged) > 8*time.Second {
				// if number > origin {
				// 	nodes, imgs := database.TrieDB().Size()
				// 	log.Info("Tracing chain segment", "start", origin, "end", end.NumberU64(), "current", number, "transactions", traced, "elapsed", time.Since(begin), "memory", nodes+imgs)
				// } else {
				log.Info("Preparing state for chain trace", "block", number, "start", origin, "elapsed", time.Since(begin))
				// }
				logged = time.Now()
			}
			// Retrieve the next block to trace
			block := api.hpb.BlockChain().GetBlockByNumber(number)
			if block == nil {
				failed = fmt.Errorf("block #%d not found", number)
				break
			}
			// Send the block over to the concurrent tracers (if not in the fast-forward phase)
			if number > origin {
				txs := block.Transactions()

				select {
				case tasks <- &blockTraceTask{statedb: statedb.Copy(), block: block, rootref: proot, results: make([]*txTraceResult, len(txs))}:
				case <-notifier.Closed():
					return
				}
				traced += uint64(len(txs))
			}
			// Generate the next state snapshot fast without tracing
			_, _, _, err := api.hpb.BlockChain().Processor().Process(block, statedb)
			if err != nil {
				failed = err
				break
			}
			// Finalize the state so any modifications are written to the trie
			root, err := statedb.CommitTo(api.hpb.HpbDb, false)
			if err != nil {
				failed = err
				break
			}
			if err := statedb.Reset(root); err != nil {
				failed = err
				break
			}
			// // Reference the trie twice, once for us, once for the tracer
			// database.TrieDB().Reference(root, common.Hash{})
			// if number >= origin {
			// 	database.TrieDB().Reference(root, common.Hash{})
			// }
			// // Dereference all past tries we ourselves are done working with
			// if proot != (common.Hash{}) {
			// 	database.TrieDB().Dereference(proot)
			// }
			// proot = root
			// TODO(karalabe): Do we need the preimages? Won't they accumulate too much?
		}
	}()

	// Keep reading the trace results and stream the to the user
	go func() {
		var (
			done = make(map[uint64]*blockTraceResult)
			next = origin + 1
		)
		for res := range results {
			// Queue up next received result
			result := &blockTraceResult{
				Block:  hexutil.Uint64(res.block.NumberU64()),
				Hash:   res.block.Hash(),
				Traces: res.results,
			}
			done[uint64(result.Block)] = result

			// Dereference any paret tries held in memory by this task
			//database.TrieDB().Dereference(res.rootref)

			// Stream completed traces to the user, aborting on the first error
			for result, ok := done[next]; ok; result, ok = done[next] {
				if len(result.Traces) > 0 || next == end.NumberU64() {
					notifier.Notify(sub.ID, result)
				}
				delete(done, next)
				next++
			}
		}
	}()
	return sub, nil
}

// TraceBlockByNumber returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceBlockByNumber(ctx context.Context, number rpc.BlockNumber, config *TraceConfig) ([]*txTraceResult, error) {
	// Fetch the block that we want to trace
	var block *types.Block

	switch number {
	case rpc.PendingBlockNumber:
		block = api.hpb.BlockChain().CurrentBlock()
	case rpc.LatestBlockNumber:
		block = api.hpb.BlockChain().CurrentBlock()
	default:
		block = api.hpb.BlockChain().GetBlockByNumber(uint64(number))
	}
	// Trace the block if it was found
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", number)
	}
	if number >= rpc.BlockNumber(consensus.StageNumberEvmV2) && number < rpc.BlockNumber(consensus.StateNumberEvmRevert) {
		return api.traceBlock_evm(ctx, block, config)
	}
	return api.traceBlock(ctx, block, config)
}

// TraceBlockByHash returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceBlockByHash(ctx context.Context, hash common.Hash, config *TraceConfig) ([]*txTraceResult, error) {
	block := api.hpb.BlockChain().GetBlockByHash(hash)
	if block == nil {
		return nil, fmt.Errorf("block %#x not found", hash)
	}
	if block.Number().Uint64() >= consensus.StageNumberEvmV2 && block.Number().Uint64() < consensus.StateNumberEvmRevert {
		return api.traceBlock_evm(ctx, block, config)
	}
	return api.traceBlock(ctx, block, config)
}

// TraceBlock returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceBlock(ctx context.Context, blob hexutil.Bytes, config *TraceConfig) ([]*txTraceResult, error) {
	block := new(types.Block)
	if err := rlp.Decode(bytes.NewReader(blob), block); err != nil {
		return nil, fmt.Errorf("could not decode block: %v", err)
	}
	if block.Number().Uint64() >= consensus.StageNumberEvmV2 && block.Number().Uint64() < consensus.StateNumberEvmRevert {
		return api.traceBlock_evm(ctx, block, config)
	}
	return api.traceBlock(ctx, block, config)
}

// TraceBlockFromFile returns the structured logs created during the execution of
// EVM and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceBlockFromFile(ctx context.Context, file string, config *TraceConfig) ([]*txTraceResult, error) {
	blob, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %v", err)
	}
	return api.TraceBlock(ctx, blob, config)
}

// TraceBadBlock returns the structured logs created during the execution of
// EVM against a block pulled from the pool of bad ones and returns them as a JSON
// object.
func (api *PrivateDebugAPI) TraceBadBlock(ctx context.Context, hash common.Hash, config *TraceConfig) ([]*txTraceResult, error) {
	blocks := api.hpb.BlockChain().BadBlocks()
	for _, block := range blocks {
		if block.Hash() == hash {
			if block.Number().Uint64() >= consensus.StageNumberEvmV2 && block.Number().Uint64() < consensus.StateNumberEvmRevert {
				return api.traceBlock_evm(ctx, block, config)
			}
			return api.traceBlock(ctx, block, config)
		}
	}
	return nil, fmt.Errorf("bad block %#x not found", hash)
}

// StandardTraceBlockToFile dumps the structured logs created during the
// execution of EVM to the local file system and returns a list of files
// to the caller.
func (api *PrivateDebugAPI) StandardTraceBlockToFile(ctx context.Context, hash common.Hash, config *StdTraceConfig) ([]string, error) {
	block := api.hpb.BlockChain().GetBlockByHash(hash)
	if block == nil {
		return nil, fmt.Errorf("block %#x not found", hash)
	}
	if block.Number().Uint64() >= consensus.StageNumberEvmV2 && block.Number().Uint64() < consensus.StateNumberEvmRevert {
		return api.standardTraceBlockToFile_evm(ctx, block, config)
	}
	return api.standardTraceBlockToFile(ctx, block, config)
}

// StandardTraceBadBlockToFile dumps the structured logs created during the
// execution of EVM against a block pulled from the pool of bad ones to the
// local file system and returns a list of files to the caller.
func (api *PrivateDebugAPI) StandardTraceBadBlockToFile(ctx context.Context, hash common.Hash, config *StdTraceConfig) ([]string, error) {
	blocks := api.hpb.BlockChain().BadBlocks()
	for _, block := range blocks {
		if block.Hash() == hash {
			if block.Number().Uint64() >= consensus.StageNumberEvmV2 && block.Number().Uint64() < consensus.StateNumberEvmRevert {
				return api.standardTraceBlockToFile_evm(ctx, block, config)
			}
			return api.standardTraceBlockToFile(ctx, block, config)
		}
	}
	return nil, fmt.Errorf("bad block %#x not found", hash)
}

// traceBlock configures a new tracer according to the provided configuration, and
// executes all the transactions contained within. The return value will be one item
// per transaction, dependent on the requestd tracer.
func (api *PrivateDebugAPI) traceBlock(ctx context.Context, block *types.Block, config *TraceConfig) ([]*txTraceResult, error) {
	// Create the parent state database
	if err := api.hpb.Engine().VerifyHeader(api.hpb.BlockChain(), block.Header(), true, params.FastSync); err != nil {
		return nil, err
	}
	parent := api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, err := api.computeStateDB(parent, reexec)
	if err != nil {
		return nil, err
	}
	// Execute all the transaction contained within the block concurrently
	var (
		signer = types.MakeSigner(api.hpb.BlockChain().Config())

		txs     = block.Transactions()
		results = make([]*txTraceResult, len(txs))

		pend = new(sync.WaitGroup)
		jobs = make(chan *txTraceTask, len(txs))
	)
	threads := runtime.NumCPU()
	if threads > len(txs) {
		threads = len(txs)
	}
	blockCtx := hvm.NewEVMContextWithoutMessage(block.Header(), api.hpb.BlockChain(), nil)
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()
			// Fetch and execute the next transaction trace tasks
			for task := range jobs {
				msg, _ := txs[task.index].AsMessage(signer)
				res, err := api.traceTx(ctx, msg, blockCtx, task.statedb, config, block.Header())
				if err != nil {
					results[task.index] = &txTraceResult{Error: err.Error()}
					continue
				}
				results[task.index] = &txTraceResult{Result: res}
			}
		}()
	}
	// Feed the transactions into the tracers and return
	var failed error
	for i, tx := range txs {
		// Send the trace task over for execution
		jobs <- &txTraceTask{statedb: statedb.Copy(), index: i}

		// Generate the next state snapshot fast without tracing
		msg, _ := tx.AsMessage(signer)
		txContext := hvm.NewEVMContextWithMessage(blockCtx, msg)

		vmenv := vm.NewEVM(txContext, statedb, api.hpb.BlockChain().Config(), vm.Config{})
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.Gas()), block.Header()); err != nil {
			failed = err
			break
		}
		statedb.Finalise(false)
	}
	close(jobs)
	pend.Wait()

	// If execution failed in between, abort
	if failed != nil {
		return nil, failed
	}
	return results, nil
}

// standardTraceBlockToFile configures a new tracer which uses standard JSON output,
// and traces either a full block or an individual transaction. The return value will
// be one filename per transaction traced.
func (api *PrivateDebugAPI) standardTraceBlockToFile(ctx context.Context, block *types.Block, config *StdTraceConfig) ([]string, error) {
	// If we're tracing a single transaction, make sure it's present
	if config != nil && config.TxHash != (common.Hash{}) {
		if !containsTx(block, config.TxHash) {
			return nil, fmt.Errorf("transaction %#x not found in block", config.TxHash)
		}
	}
	// Create the parent state database
	if err := api.hpb.Engine().VerifyHeader(api.hpb.BlockChain(), block.Header(), true, params.FastSync); err != nil {
		return nil, err
	}
	parent := api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, err := api.computeStateDB(parent, reexec)
	if err != nil {
		return nil, err
	}
	// Retrieve the tracing configurations, or use default values
	var (
		logConfig vm.LogConfig
		txHash    common.Hash
	)
	if config != nil {
		logConfig = config.LogConfig
		txHash = config.TxHash
	}
	logConfig.Debug = true

	// Execute transaction, either tracing all or just the requested one
	var (
		signer      = types.MakeSigner(api.hpb.BlockChain().Config())
		dumps       []string
		chainConfig = api.hpb.BlockChain().Config()
		vmctx       = hvm.NewEVMContextWithoutMessage(block.Header(), api.hpb.BlockChain(), nil)
		canon       = true
	)
	// Check if there are any overrides: the caller may wish to enable a future
	// fork when executing this block. Note, such overrides are only applicable to the
	// actual specified block, not any preceding blocks that we have to go through
	// in order to obtain the state.
	// Therefore, it's perfectly valid to specify `"futureForkBlock": 0`, to enable `futureFork`

	if config != nil && config.Overrides != nil {
		// Copy the config, to not screw up the main config
		// Note: the Clique-part is _not_ deep copied
		chainConfigCopy := new(params.ChainConfig)
		*chainConfigCopy = *chainConfig
		chainConfig = chainConfigCopy
	}
	for i, tx := range block.Transactions() {
		// Prepare the trasaction for un-traced execution
		var (
			msg, _    = tx.AsMessage(signer)
			txContext = hvm.NewEVMContextWithMessage(vmctx, msg)
			vmConf    vm.Config
			dump      *os.File
			writer    *bufio.Writer
			err       error
		)
		// If the transaction needs tracing, swap out the configs
		if tx.Hash() == txHash || txHash == (common.Hash{}) {
			// Generate a unique temporary file to dump it into
			prefix := fmt.Sprintf("block_%#x-%d-%#x-", block.Hash().Bytes()[:4], i, tx.Hash().Bytes()[:4])
			if !canon {
				prefix = fmt.Sprintf("%valt-", prefix)
			}
			dump, err = ioutil.TempFile(os.TempDir(), prefix)
			if err != nil {
				return nil, err
			}
			dumps = append(dumps, dump.Name())

			// Swap out the noop logger to the standard tracer
			writer = bufio.NewWriter(dump)
			vmConf = vm.Config{
				Debug:                   true,
				Tracer:                  vm.NewJSONLogger(&logConfig, writer),
				EnablePreimageRecording: true,
			}
		}
		// Execute the transaction and flush any traces to disk
		vmenv := vm.NewEVM(txContext, statedb, chainConfig, vmConf)
		_, err = core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.Gas()), block.Header())
		if writer != nil {
			writer.Flush()
		}
		if dump != nil {
			dump.Close()
			log.Info("Wrote standard trace", "file", dump.Name())
		}
		if err != nil {
			return dumps, err
		}
		statedb.Finalise(false)

		// If we've traced the transaction we were looking for, abort
		if tx.Hash() == txHash {
			break
		}
	}
	return dumps, nil
}

// containsTx reports whether the transaction with a certain hash
// is contained within the specified block.
func containsTx(block *types.Block, hash common.Hash) bool {
	for _, tx := range block.Transactions() {
		if tx.Hash() == hash {
			return true
		}
	}
	return false
}

// computeStateDB retrieves the state database associated with a certain block.
// If no state is locally available for the given block, a number of blocks are
// attempted to be reexecuted to generate the desired state.
func (api *PrivateDebugAPI) computeStateDB(block *types.Block, reexec uint64) (*state.StateDB, error) {
	// If we have the state fully available, use that
	statedb, err := api.hpb.BlockChain().StateAt(block.Root())
	if err == nil {
		return statedb, nil
	}
	// Otherwise try to reexec blocks until we find a state or reach our limit
	origin := block.NumberU64()
	database := state.NewDatabase(api.hpb.ChainDb())

	for i := uint64(0); i < reexec; i++ {
		block = api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
		if block == nil {
			break
		}
		if statedb, err = state.New(block.Root(), database); err == nil {
			break
		}
	}
	if err != nil {
		switch err.(type) {
		case *trie.MissingNodeError:
			return nil, fmt.Errorf("required historical state unavailable (reexec=%d)", reexec)
		default:
			return nil, err
		}
	}
	// State was available at historical point, regenerate
	var (
		start  = time.Now()
		logged time.Time
		//proot  common.Hash
	)
	for block.NumberU64() < origin {
		// Print progress logs if long enough time elapsed
		if time.Since(logged) > 8*time.Second {
			log.Info("Regenerating historical state", "block", block.NumberU64()+1, "target", origin, "remaining", origin-block.NumberU64()-1, "elapsed", time.Since(start))
			logged = time.Now()
		}
		number := block.NumberU64()
		// Retrieve the next block to regenerate and process it
		if block = api.hpb.BlockChain().GetBlockByNumber(number + 1); block == nil {
			return nil, fmt.Errorf("block #%d not found", number+1)
		}
		_, _, _, err := api.hpb.BlockChain().Processor().Process(block, statedb)
		if err != nil {
			return nil, fmt.Errorf("processing block %d failed: %v", block.NumberU64(), err)
		}
		// Finalize the state so any modifications are written to the trie
		root, err := statedb.CommitTo(api.hpb.ChainDb(), false)
		if err != nil {
			return nil, err
		}
		if err := statedb.Reset(root); err != nil {
			return nil, fmt.Errorf("state reset after block %d failed: %v", block.NumberU64(), err)
		}
		// database.TrieDB().Reference(root, common.Hash{})
		// if proot != (common.Hash{}) {
		// 	database.TrieDB().Dereference(proot)
		// }
		// proot = root
	}
	//nodes, imgs := database.TrieDB().Size()
	//log.Info("Historical state regenerated", "block", block.NumberU64(), "elapsed", time.Since(start), "nodes", nodes, "preimages", imgs)
	log.Info("Historical state regenerated", "block", block.NumberU64(), "elapsed", time.Since(start))
	return statedb, nil
}

// TraceTransaction returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceTransaction(ctx context.Context, hash common.Hash, config *TraceConfig) (interface{}, error) {
	// Retrieve the transaction and assemble its EVM context
	tx, blockHash, _, index := core.GetTransaction(api.hpb.ChainDb(), hash)
	if tx == nil {
		return nil, fmt.Errorf("transaction %#x not found", hash)
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	// Retrieve the block
	block := api.hpb.BlockChain().GetBlockByHash(blockHash)
	if block == nil {
		return nil, fmt.Errorf("block %#x not found", blockHash)
	}
	msg, vmctx, statedb, err := api.computeTxEnv(block, int(index), reexec)
	if err != nil {
		return nil, err
	}
	if block.NumberU64() >= consensus.StageNumberEvmV2 && block.NumberU64() < consensus.StateNumberEvmRevert {
		return api.traceTx_evm(ctx, msg, statedb, config, block.Header())
	}
	// Trace the transaction and return
	return api.traceTx(ctx, msg, vmctx, statedb, config, block.Header())
}

// TraceCall lets you trace a given eth_call. It collects the structured logs created during the execution of EVM
// if the given transaction was added on top of the provided block and returns them as a JSON object.
// You can provide -2 as a block number to trace on top of the pending block.
func (api *PrivateDebugAPI) TraceCall(ctx context.Context, args hpbapi.CallArgs, blockNrOrHash rpc.BlockNumberOrHash, config *TraceConfig) (interface{}, error) {
	// First try to retrieve the state
	statedb, header, err := api.hpb.ApiBackend.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if err != nil {
		// Try to retrieve the specified block
		var block *types.Block
		if hash, ok := blockNrOrHash.Hash(); ok {
			block = api.hpb.BlockChain().GetBlockByHash(hash)
		} else if number, ok := blockNrOrHash.Number(); ok {
			block = api.hpb.BlockChain().GetBlockByNumber(uint64(number))
		}
		if block == nil {
			return nil, fmt.Errorf("block %v not found: %v", blockNrOrHash, err)
		}
		// try to recompute the state
		reexec := defaultTraceReexec
		if config != nil && config.Reexec != nil {
			reexec = *config.Reexec
		}
		_, _, statedb, err = api.computeTxEnv(block, 0, reexec)
		if err != nil {
			return nil, err
		}
	}
	// Execute the trace
	msg := args.ToMessage(api.hpb.ApiBackend.RPCGasCap())
	if header.Number.Uint64() >= consensus.StageNumberEvmV2 && header.Number.Uint64() < consensus.StateNumberEvmRevert {
		return api.traceTx_evm(ctx, msg, statedb, config, header)
	}
	vmctx := hvm.NewEVMContextWithoutMessage(header, api.hpb.BlockChain(), nil)
	return api.traceTx(ctx, msg, vmctx, statedb, config, header)
}

// traceTx configures a new tracer according to the provided configuration, and
// executes the given message in the provided environment. The return value will
// be tracer dependent.
func (api *PrivateDebugAPI) traceTx(ctx context.Context, message vmcore.Message, vmctx vm.Context, statedb *state.StateDB, config *TraceConfig, header *types.Header) (interface{}, error) {
	// Assemble the structured logger or the JavaScript tracer
	var (
		tracer    vm.Tracer
		err       error
		txContext = hvm.NewEVMContextWithMessage(vmctx, message)
	)
	switch {
	case config != nil && config.Tracer != nil:
		// Define a meaningful timeout of a single transaction trace
		timeout := defaultTraceTimeout
		if config.Timeout != nil {
			if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
				return nil, err
			}
		}
		// Constuct the JavaScript tracer to execute with
		if tracer, err = tracers.New(*config.Tracer); err != nil {
			return nil, err
		}
		// Handle timeouts and RPC cancellations
		deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
		go func() {
			<-deadlineCtx.Done()
			tracer.(*tracers.Tracer).Stop(errors.New("execution timeout"))
		}()
		defer cancel()

	case config == nil:
		tracer = vm.NewStructLogger(nil)

	default:
		tracer = vm.NewStructLogger(config.LogConfig)
	}
	// Run the transaction with tracing enabled.
	vmenv := vm.NewEVM(txContext, statedb, api.hpb.BlockChain().Config(), vm.Config{Debug: true, Tracer: tracer})

	result, err := core.ApplyMessage(vmenv, message, new(core.GasPool).AddGas(message.Gas()), header)
	if err != nil {
		return nil, fmt.Errorf("tracing failed: %v", err)
	}
	// Depending on the tracer type, format and return the output
	switch tracer := tracer.(type) {
	case *vm.StructLogger:
		// If the result contains a revert reason, return it.
		returnVal := fmt.Sprintf("%x", result.Return())
		if len(result.Revert()) > 0 {
			returnVal = fmt.Sprintf("%x", result.Revert())
		}
		return &hpbapi.ExecutionResult{
			Gas:         new(big.Int).SetUint64(result.UsedGas),
			Failed:      result.Failed(),
			ReturnValue: returnVal,
			StructLogs:  vmcorevm.FormatLogs(tracer.StructLogs()),
		}, nil

	case *tracers.Tracer:
		return tracer.GetResult()

	default:
		panic(fmt.Sprintf("bad tracer type %T", tracer))
	}
}

// computeTxEnv returns the execution environment of a certain transaction.
func (api *PrivateDebugAPI) computeTxEnv(block *types.Block, txIndex int, reexec uint64) (vmcore.Message, vm.Context, *state.StateDB, error) {
	// Create the parent state database
	parent := api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, vm.Context{}, nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	statedb, err := api.computeStateDB(parent, reexec)
	if err != nil {
		return nil, vm.Context{}, nil, err
	}

	if txIndex == 0 && len(block.Transactions()) == 0 {
		return nil, vm.Context{}, statedb, nil
	}

	// Recompute transactions up to the target index.
	signer := types.MakeSigner(api.hpb.BlockChain().Config())

	for idx, tx := range block.Transactions() {
		// Assemble the transaction call message and return if the requested offset
		msg, _ := tx.AsMessage(signer)
		context := hvm.NewEVMContextWithoutMessage(block.Header(), api.hpb.BlockChain(), nil)
		txContext := hvm.NewEVMContextWithMessage(context, msg)
		if idx == txIndex {
			return msg, context, statedb, nil
		}
		// Not yet the searched for transaction, execute on top of the current state
		vmenv := vm.NewEVM(txContext, statedb, api.hpb.BlockChain().Config(), vm.Config{})
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.Gas().Uint64()), block.Header()); err != nil {
			return nil, vm.Context{}, nil, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		statedb.Finalise(false)
	}
	return nil, vm.Context{}, nil, fmt.Errorf("transaction index %d out of range for block %#x", txIndex, block.Hash())
}
func (api *PrivateDebugAPI) traceBlock_evm(ctx context.Context, block *types.Block, config *TraceConfig) ([]*txTraceResult, error) {
	// Create the parent state database
	if err := api.hpb.Engine().VerifyHeader(api.hpb.BlockChain(), block.Header(), true, params.FastSync); err != nil {
		return nil, err
	}
	parent := api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, err := api.computeStateDB(parent, reexec)
	if err != nil {
		return nil, err
	}
	// Execute all the transaction contained within the block concurrently
	var (
		signer = types.MakeSigner(api.hpb.BlockChain().Config())

		txs     = block.Transactions()
		results = make([]*txTraceResult, len(txs))

		pend = new(sync.WaitGroup)
		jobs = make(chan *txTraceTask, len(txs))
	)
	threads := runtime.NumCPU()
	if threads > len(txs) {
		threads = len(txs)
	}
	blockCtx := evm.NewEVMBlockContext(block.Header(), api.hpb.BlockChain(), nil)
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()
			// Fetch and execute the next transaction trace tasks
			for task := range jobs {
				msg, _ := txs[task.index].AsMessage(signer)
				res, err := api.traceTx_evm(ctx, msg, task.statedb, config, block.Header())
				if err != nil {
					results[task.index] = &txTraceResult{Error: err.Error()}
					continue
				}
				results[task.index] = &txTraceResult{Result: res}
			}
		}()
	}
	// Feed the transactions into the tracers and return
	var failed error
	for i, tx := range txs {
		// Send the trace task over for execution
		jobs <- &txTraceTask{statedb: statedb.Copy(), index: i}

		// Generate the next state snapshot fast without tracing
		msg, _ := tx.AsMessage(signer)
		txContext := evm.NewEVMTxContext(msg)

		vmenv := eevm.NewEVM(blockCtx, txContext, statedb, api.hpb.BlockChain().Config(), eevm.Config{})
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.Gas()), block.Header()); err != nil {
			failed = err
			break
		}
		statedb.Finalise(false)
	}
	close(jobs)
	pend.Wait()

	// If execution failed in between, abort
	if failed != nil {
		return nil, failed
	}
	return results, nil
}

func getLogConfig(logconfig vm.LogConfig) eevm.LogConfig {
	return eevm.LogConfig{
		EnableMemory:     !logconfig.DisableMemory,
		DisableStack:     logconfig.DisableStack,
		DisableStorage:   logconfig.DisableStorage,
		EnableReturnData: !logconfig.DisableReturnData,
		Debug:            logconfig.Debug,
		Limit:            logconfig.Limit,
		Overrides:        logconfig.Overrides,
	}
}

func (api *PrivateDebugAPI) standardTraceBlockToFile_evm(ctx context.Context, block *types.Block, config *StdTraceConfig) ([]string, error) {
	// If we're tracing a single transaction, make sure it's present
	if config != nil && config.TxHash != (common.Hash{}) {
		if !containsTx(block, config.TxHash) {
			return nil, fmt.Errorf("transaction %#x not found in block", config.TxHash)
		}
	}
	// Create the parent state database
	if err := api.hpb.Engine().VerifyHeader(api.hpb.BlockChain(), block.Header(), true, params.FastSync); err != nil {
		return nil, err
	}
	parent := api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, err := api.computeStateDB(parent, reexec)
	if err != nil {
		return nil, err
	}
	// Retrieve the tracing configurations, or use default values
	var (
		logConfig eevm.LogConfig
		txHash    common.Hash
	)
	if config != nil {
		logConfig = getLogConfig(config.LogConfig)
		txHash = config.TxHash
	}
	logConfig.Debug = true

	// Execute transaction, either tracing all or just the requested one
	var (
		signer      = types.MakeSigner(api.hpb.BlockChain().Config())
		dumps       []string
		chainConfig = api.hpb.BlockChain().Config()
		vmctx       = evm.NewEVMBlockContext(block.Header(), api.hpb.BlockChain(), nil)
		canon       = true
	)
	// Check if there are any overrides: the caller may wish to enable a future
	// fork when executing this block. Note, such overrides are only applicable to the
	// actual specified block, not any preceding blocks that we have to go through
	// in order to obtain the state.
	// Therefore, it's perfectly valid to specify `"futureForkBlock": 0`, to enable `futureFork`

	if config != nil && config.Overrides != nil {
		// Copy the config, to not screw up the main config
		// Note: the Clique-part is _not_ deep copied
		chainConfigCopy := new(params.ChainConfig)
		*chainConfigCopy = *chainConfig
		chainConfig = chainConfigCopy
	}
	for i, tx := range block.Transactions() {
		// Prepare the trasaction for un-traced execution
		var (
			msg, _    = tx.AsMessage(signer)
			txContext = evm.NewEVMTxContext(msg)
			vmConf    eevm.Config
			dump      *os.File
			writer    *bufio.Writer
			err       error
		)
		// If the transaction needs tracing, swap out the configs
		if tx.Hash() == txHash || txHash == (common.Hash{}) {
			// Generate a unique temporary file to dump it into
			prefix := fmt.Sprintf("block_%#x-%d-%#x-", block.Hash().Bytes()[:4], i, tx.Hash().Bytes()[:4])
			if !canon {
				prefix = fmt.Sprintf("%valt-", prefix)
			}
			dump, err = ioutil.TempFile(os.TempDir(), prefix)
			if err != nil {
				return nil, err
			}
			dumps = append(dumps, dump.Name())

			// Swap out the noop logger to the standard tracer
			writer = bufio.NewWriter(dump)
			vmConf = eevm.Config{
				Debug:                   true,
				Tracer:                  eevm.NewJSONLogger(&logConfig, writer),
				EnablePreimageRecording: true,
			}
		}
		// Execute the transaction and flush any traces to disk
		vmenv := eevm.NewEVM(vmctx, txContext, statedb, chainConfig, vmConf)
		_, err = core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.Gas()), block.Header())
		if writer != nil {
			writer.Flush()
		}
		if dump != nil {
			dump.Close()
			log.Info("Wrote standard trace", "file", dump.Name())
		}
		if err != nil {
			return dumps, err
		}
		statedb.Finalise(false)

		// If we've traced the transaction we were looking for, abort
		if tx.Hash() == txHash {
			break
		}
	}
	return dumps, nil
}

func (api *PrivateDebugAPI) traceTx_evm(ctx context.Context, message vmcore.Message, statedb *state.StateDB, config *TraceConfig, header *types.Header) (interface{}, error) {
	// Assemble the structured logger or the JavaScript tracer
	var (
		tracer    eevm.EVMLogger
		err       error
		txContext = evm.NewEVMTxContext(message)
	)
	switch {
	case config != nil && config.Tracer != nil:
		// Define a meaningful timeout of a single transaction trace
		timeout := defaultTraceTimeout
		if config.Timeout != nil {
			if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
				return nil, err
			}
		}
		// Constuct the JavaScript tracer to execute with
		if tracer, err = tracers.New2(*config.Tracer); err != nil {
			return nil, err
		}
		// Handle timeouts and RPC cancellations
		deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
		go func() {
			<-deadlineCtx.Done()
			tracer.(*tracers.JsTracer).Stop(errors.New("execution timeout"))
		}()
		defer cancel()

	default:
		tracer = eevm.NewStructLogger(nil)
	}
	blockContext := evm.NewEVMBlockContext(header, api.hpb.BlockChain(), nil)
	vmenv := eevm.NewEVM(blockContext, txContext, statedb, api.hpb.BlockChain().Config(), eevm.Config{Debug: true, Tracer: tracer})

	result, err := core.ApplyMessage(vmenv, message, new(core.GasPool).AddGas(message.Gas()), header)
	if err != nil {
		return nil, fmt.Errorf("tracing failed: %v", err)
	}
	// Depending on the tracer type, format and return the output
	switch tracer := tracer.(type) {
	case *eevm.StructLogger:
		// If the result contains a revert reason, return it.
		returnVal := fmt.Sprintf("%x", result.Return())
		if len(result.Revert()) > 0 {
			returnVal = fmt.Sprintf("%x", result.Revert())
		}
		return &hpbapi.ExecutionResult{
			Gas:         new(big.Int).SetUint64(result.UsedGas),
			Failed:      result.Failed(),
			ReturnValue: returnVal,
			StructLogs:  vmcorevm.FormatLogs2(tracer.StructLogs()),
		}, nil

	case *tracers.JsTracer:
		return tracer.GetResult()

	default:
		panic(fmt.Sprintf("bad tracer type %T", tracer))
	}
}
