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

package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/crypto/sha3"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/common/trie"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus/prometheus"
	"github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/internal/hpbapi"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/node/db"
)

const defaultTraceTimeout = 5 * time.Second
const defaultHashlen = 66
const mindistance = 10
const pivotsynfull = 5000

type AccountDiff struct {
	addr       common.Address
	prebalance *big.Int
	balance    *big.Int
}

type StateDiff struct {
	txhash      common.Hash
	accountdiff []AccountDiff
	evmdiff     string
}

func (accountdiff AccountDiff) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"addr":   accountdiff.addr,
		"before": accountdiff.prebalance,
		"after":  accountdiff.balance,
	})
}

func (statediff StateDiff) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"txhash":     statediff.txhash,
		"state_diff": statediff.accountdiff,
		"evmdiff":    statediff.evmdiff,
	})
}

// PublicHpbAPI provides an API to access Hpb full node-related
// information.
type PublicHpbAPI struct {
	e *Node
}

// NewPublicHpbAPI creates a new Hpb protocol API for full nodes.
func NewPublicHpbAPI(e *Node) *PublicHpbAPI {
	return &PublicHpbAPI{e}
}

// Hpberbase is the address that mining rewards will be send to
func (api *PublicHpbAPI) Hpberbase() (common.Address, error) {
	return api.e.Hpberbase()
}

// Coinbase is the address that mining rewards will be send to (alias for Hpberbase)
func (api *PublicHpbAPI) Coinbase() (common.Address, error) {
	return api.Hpberbase()
}

// Mining returns the miner is mining
func (api *PublicHpbAPI) Mining() bool {
	return api.e.miner.Mining()
}

func (api *PublicHpbAPI) GetStatediffbyblockandTx(data string, hash string) string {
	log.Debug("Replay_Block", "blockhash", data, "lendata", len(data))

	blockchain := api.e.BlockChain()
	var block *types.Block
	var txhash common.Hash
	if strings.Index(data, "0x") == 0 && len(data) == defaultHashlen {
		log.Debug("Replay_Block", "blockhash", common.HexToHash(data))
		block = blockchain.GetBlockByHash(common.HexToHash(data))

	} else if len(data) > 0 {
		blockNumber, _ := strconv.ParseUint(data, 0, 64)
		log.Debug("Replay_Block", "blocknumber", blockNumber)
		block = blockchain.GetBlockByNumber(blockNumber)
	}
	if strings.Index(hash, "0x") == 0 && len(hash) == defaultHashlen {
		txhash = common.HexToHash(hash)
		log.Debug("getblockbyhash", "hash", txhash)
		if tx, blockHash, number, _ := bc.GetTransaction(api.e.ChainDb(), txhash); tx != nil {
			block = blockchain.GetBlock(blockHash, number)
		}
	}
	if block == nil {
		return string("getblockerror")
	}

	statedb, err := blockchain.StateAt(blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1).Root())
	statedbpre, err := blockchain.StateAt(blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1).Root())
	if err != nil {
		return string("getstateerror")
	}

	var (
		gp            = new(bc.GasPool).AddGas(block.GasLimit())
		header        = block.Header()
		totalUsedGas  = big.NewInt(0)
		allAddress    = make(map[common.Address]*big.Int)
		allState_Diff = []StateDiff{}
	)

	for i, tx := range block.Transactions() {
		state_diff := StateDiff{txhash: tx.Hash()}
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		if (tx.To() == nil || len(statedb.GetCode(*tx.To())) > 0) && len(tx.Data()) > 0 {
			evmstatediff, _, _, _ := bc.ApplyTransaction(blockchain.Config(), blockchain, nil, gp, statedb, header, tx, totalUsedGas)
			log.Debug("evmdiff", "evmstatediff", evmstatediff)
			state_diff.evmdiff = evmstatediff
		} else {
			bc.ApplyTransactionNonContract(blockchain.Config(), blockchain, nil, gp, statedb, header, tx, totalUsedGas)
		}

		stateOjects := statedb.GetStateObjects()
		for _, addr := range stateOjects {
			_, ok := allAddress[addr]
			if ok != true {
				allAddress[addr] = statedbpre.GetBalance(addr)
			}
			accountdiff := AccountDiff{addr: addr, prebalance: allAddress[addr], balance: statedb.GetBalance(addr)}
			state_diff.accountdiff = append(state_diff.accountdiff, accountdiff)
			allAddress[addr] = accountdiff.balance
			log.Debug("diff_state", "txhash", state_diff.txhash, "addr", accountdiff.addr, "prebalance", accountdiff.prebalance, "balance", accountdiff.balance, "diff", new(big.Int).Sub(accountdiff.balance, accountdiff.prebalance))
		}
		allState_Diff = append(allState_Diff, state_diff)
		if txhash == tx.Hash() {
			jsons, errs := json.Marshal(state_diff)
			log.Debug("json----", "jsons", string(jsons), "errs", errs)
			return string(jsons)
		}

	}

	jsons, errs := json.Marshal(allState_Diff)
	log.Debug("json----", "jsons", string(jsons), "errs", errs)
	return string(jsons)
}
func (api *PublicHpbAPI) GetStatediffbyblock(data string) string {
	log.Debug("Replay_Block", "blockhash", data, "lendata", len(data))

	blockchain := api.e.BlockChain()
	var block *types.Block
	if strings.Index(data, "0x") == 0 && len(data) == defaultHashlen {
		log.Debug("Replay_Block", "blockhash", common.HexToHash(data))
		block = blockchain.GetBlockByHash(common.HexToHash(data))
	} else {
		blockNumber, _ := strconv.ParseUint(data, 0, 64)
		log.Debug("Replay_Block", "blocknumber", blockNumber)
		block = blockchain.GetBlockByNumber(blockNumber)
	}

	if block == nil {
		return string("getblockerror")
	}

	statedb, err := blockchain.StateAt(blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1).Root())
	statedbpre, err := blockchain.StateAt(blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1).Root())
	if err != nil {
		return string("getstateerror")
	}

	var (
		gp            = new(bc.GasPool).AddGas(block.GasLimit())
		header        = block.Header()
		totalUsedGas  = big.NewInt(0)
		allAddress    = make(map[common.Address]*big.Int)
		allState_Diff = []StateDiff{}
	)

	for i, tx := range block.Transactions() {
		state_diff := StateDiff{txhash: tx.Hash()}
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		if (tx.To() == nil || len(statedb.GetCode(*tx.To())) > 0) && len(tx.Data()) > 0 {
			evmstatediff, _, _, _ := bc.ApplyTransaction(blockchain.Config(), blockchain, nil, gp, statedb, header, tx, totalUsedGas)
			log.Debug("evmdiff", "evmstatediff", evmstatediff)
			state_diff.evmdiff = evmstatediff
		} else {
			bc.ApplyTransactionNonContract(blockchain.Config(), blockchain, nil, gp, statedb, header, tx, totalUsedGas)
		}

		stateOjects := statedb.GetStateObjects()
		for _, addr := range stateOjects {
			_, ok := allAddress[addr]
			if ok != true {
				allAddress[addr] = statedbpre.GetBalance(addr)
			}
			accountdiff := AccountDiff{addr: addr, prebalance: allAddress[addr], balance: statedb.GetBalance(addr)}
			state_diff.accountdiff = append(state_diff.accountdiff, accountdiff)
			allAddress[addr] = accountdiff.balance
			log.Debug("diff_state", "txhash", state_diff.txhash, "addr", accountdiff.addr, "prebalance", accountdiff.prebalance, "balance", accountdiff.balance, "diff", new(big.Int).Sub(accountdiff.balance, accountdiff.prebalance))
		}
		allState_Diff = append(allState_Diff, state_diff)

	}
	jsons, errs := json.Marshal(allState_Diff)
	log.Debug("json----", "jsons", string(jsons), "errs", errs)
	return string(jsons)
}

// PrivateMinerAPI provides private RPC methods tso control the miner.
// These methods can be abused by external users and must be considered insecure for use by untrusted users.
type PrivateMinerAPI struct {
	e *Node
}

// NewPrivateMinerAPI create a new RPC service which controls the miner of this node.
func NewPrivateMinerAPI(e *Node) *PrivateMinerAPI {
	return &PrivateMinerAPI{e: e}
}

// Start the miner with the given number of threads. If threads is nil the number
// of workers started is equal to the number of logical CPUs that are usable by
// this process. If mining is already running, this method adjust the number of
// threads allowed to use.
func (api *PrivateMinerAPI) Start(threads *int) error {
	// Set the number of threads if the seal engine supports it
	log.Info("miner start : :")
	if threads == nil {
		threads = new(int)
	} else if *threads == 0 {
		*threads = -1 // Disable the miner from within
	}
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := api.e.Hpbengine.(threaded); ok {
		log.Info("Updated mining threads", "threads", *threads)
		th.SetThreads(*threads)
	}
	// Start the miner and return
	if !api.e.IsMining() {
		// Propagate the initial price point to the transaction pool
		api.e.lock.RLock()
		price := api.e.gasPrice
		api.e.lock.RUnlock()

		api.e.Hpbtxpool.SetGasPrice(price)
		return api.e.StartMining(true)
	}
	return nil
}

// Stop the miner
func (api *PrivateMinerAPI) Stop() bool {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := api.e.Hpbengine.(threaded); ok {
		th.SetThreads(-1)
	}
	api.e.StopMining()
	return true
}

// SetExtra sets the extra data string that is included when this miner mines a block.
func (api *PrivateMinerAPI) SetExtra(extra string) (bool, error) {
	if err := api.e.Miner().SetExtra([]byte(extra)); err != nil {
		return false, err
	}
	return true, nil
}

// SetGasPrice sets the minimum accepted gas price for the miner.
func (api *PrivateMinerAPI) SetGasPrice(gasPrice hexutil.Big) bool {
	api.e.lock.Lock()
	api.e.gasPrice = (*big.Int)(&gasPrice)
	api.e.lock.Unlock()

	api.e.Hpbtxpool.SetGasPrice((*big.Int)(&gasPrice))
	return true
}

// SetHpberbase sets the hpberbase of the miner
func (api *PrivateMinerAPI) SetHpberbase(hpberbase common.Address) bool {
	api.e.SetHpberbase(hpberbase)
	return true
}

// PrivateAdminAPI is the collection of Hpb full node-related APIs
// exposed over the private admin endpoint.
type PrivateAdminAPI struct {
	hpb *Node
}

// NewPrivateAdminAPI creates a new API definition for the full node private
// admin methods of the Hpb service.
func NewPrivateAdminAPI(hpb *Node) *PrivateAdminAPI {
	return &PrivateAdminAPI{hpb: hpb}
}

// ExportChain exports the current blockchain into a local file.
func (api *PrivateAdminAPI) ExportChain(file string) (bool, error) {
	// Make sure we can create the file to export into
	out, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return false, err
	}
	defer out.Close()

	var writer io.Writer = out
	if strings.HasSuffix(file, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}

	// Export the blockchain
	if err := api.hpb.BlockChain().Export(writer); err != nil {
		return false, err
	}
	return true, nil
}

func hasAllBlocks(chain *bc.BlockChain, bs []*types.Block) bool {
	for _, b := range bs {
		if !chain.HasBlock(b.Hash(), b.NumberU64()) {
			return false
		}
	}

	return true
}

// ImportChain imports a blockchain from a local file.
func (api *PrivateAdminAPI) ImportChain(file string) (bool, error) {
	// Make sure the can access the file to import
	in, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer in.Close()

	var reader io.Reader = in
	if strings.HasSuffix(file, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return false, err
		}
	}

	// Run actual the import in pre-configured batches
	stream := rlp.NewStream(reader, 0)

	blocks, index := make([]*types.Block, 0, 2500), 0
	for batch := 0; ; batch++ {
		// Load a batch of blocks from the input file
		for len(blocks) < cap(blocks) {
			block := new(types.Block)
			if err := stream.Decode(block); err == io.EOF {
				break
			} else if err != nil {
				return false, fmt.Errorf("block %d: failed to parse: %v", index, err)
			}
			blocks = append(blocks, block)
			index++
		}
		if len(blocks) == 0 {
			break
		}

		if hasAllBlocks(api.hpb.BlockChain(), blocks) {
			blocks = blocks[:0]
			continue
		}
		// Import the batch and reset the buffer
		if _, err := api.hpb.BlockChain().InsertChain(blocks); err != nil {
			return false, fmt.Errorf("batch %d: failed to insert: %v", batch, err)
		}
		blocks = blocks[:0]
	}
	return true, nil
}

// PublicDebugAPI is the collection of Hpb full node APIs exposed
// over the public debugging endpoint.
type PublicDebugAPI struct {
	hpb *Node
}

// NewPublicDebugAPI creates a new API definition for the full node-
// related public debug methods of the Hpb service.
func NewPublicDebugAPI(hpb *Node) *PublicDebugAPI {
	return &PublicDebugAPI{hpb: hpb}
}

// DumpBlock retrieves the entire state of the database at a given block.
func (api *PublicDebugAPI) DumpBlock(blockNr rpc.BlockNumber) (state.Dump, error) {
	if blockNr == rpc.PendingBlockNumber {
		// If we're dumping the pending state, we need to request
		// both the pending block as well as the pending state from
		// the miner and operate on those
		_, stateDb := api.hpb.miner.Pending()
		return stateDb.RawDump(), nil
	}
	var block *types.Block
	if blockNr == rpc.LatestBlockNumber {
		block = api.hpb.Hpbbc.CurrentBlock()
	} else {
		block = api.hpb.Hpbbc.GetBlockByNumber(uint64(blockNr))
	}
	if block == nil {
		return state.Dump{}, fmt.Errorf("block #%d not found", blockNr)
	}
	stateDb, err := api.hpb.BlockChain().StateAt(block.Root())
	if err != nil {
		return state.Dump{}, err
	}
	return stateDb.RawDump(), nil
}

// PrivateDebugAPI is the collection of Hpb full node APIs exposed over
// the private debugging endpoint.
type PrivateDebugAPI struct {
	config *config.ChainConfig
	hpb    *Node
}

// NewPrivateDebugAPI creates a new API definition for the full node-related
// private debug methods of the Hpb service.
func NewPrivateDebugAPI(config *config.ChainConfig, hpb *Node) *PrivateDebugAPI {
	return &PrivateDebugAPI{config: config, hpb: hpb}
}

// BlockTraceResult is the returned value when replaying a block to check for
// consensus results and full VM trace logs for all included transactions.
type BlockTraceResult struct {
	Validated  bool                  `json:"validated"`
	StructLogs []hpbapi.StructLogRes `json:"structLogs"`
	Error      string                `json:"error"`
}

// TraceArgs holds extra parameters to trace functions
type TraceArgs struct {
	*evm.LogConfig
	Tracer  *string
	Timeout *string
}

// TraceBlock processes the given block'api RLP but does not import the block in to
// the chain.
func (api *PrivateDebugAPI) TraceBlock(blockRlp []byte, config *evm.LogConfig) BlockTraceResult {
	var block types.Block
	err := rlp.Decode(bytes.NewReader(blockRlp), &block)
	if err != nil {
		return BlockTraceResult{Error: fmt.Sprintf("could not decode block: %v", err)}
	}

	validated, logs, err := api.traceBlock(&block, config)
	return BlockTraceResult{
		Validated:  validated,
		StructLogs: hpbapi.FormatLogs(logs),
		Error:      formatError(err),
	}
}

// TraceBlockFromFile loads the block'api RLP from the given file name and attempts to
// process it but does not import the block in to the chain.
func (api *PrivateDebugAPI) TraceBlockFromFile(file string, config *evm.LogConfig) BlockTraceResult {
	blockRlp, err := ioutil.ReadFile(file)
	if err != nil {
		return BlockTraceResult{Error: fmt.Sprintf("could not read file: %v", err)}
	}
	return api.TraceBlock(blockRlp, config)
}

// TraceBlockByNumber processes the block by canonical block number.
func (api *PrivateDebugAPI) TraceBlockByNumber(blockNr rpc.BlockNumber, config *evm.LogConfig) BlockTraceResult {
	// Fetch the block that we aim to reprocess
	var block *types.Block
	switch blockNr {
	case rpc.PendingBlockNumber:
		// Pending block is only known by the miner
		block = api.hpb.miner.PendingBlock()
	case rpc.LatestBlockNumber:
		block = api.hpb.Hpbbc.CurrentBlock()
	default:
		block = api.hpb.Hpbbc.GetBlockByNumber(uint64(blockNr))
	}

	if block == nil {
		return BlockTraceResult{Error: fmt.Sprintf("block #%d not found", blockNr)}
	}

	validated, logs, err := api.traceBlock(block, config)
	return BlockTraceResult{
		Validated:  validated,
		StructLogs: hpbapi.FormatLogs(logs),
		Error:      formatError(err),
	}
}

// TraceBlockByHash processes the block by hash.
func (api *PrivateDebugAPI) TraceBlockByHash(hash common.Hash, config *evm.LogConfig) BlockTraceResult {
	// Fetch the block that we aim to reprocess
	block := api.hpb.BlockChain().GetBlockByHash(hash)
	if block == nil {
		return BlockTraceResult{Error: fmt.Sprintf("block #%x not found", hash)}
	}

	validated, logs, err := api.traceBlock(block, config)
	return BlockTraceResult{
		Validated:  validated,
		StructLogs: hpbapi.FormatLogs(logs),
		Error:      formatError(err),
	}
}

// traceBlock processes the given block but does not save the state.
func (api *PrivateDebugAPI) traceBlock(block *types.Block, logConfig *evm.LogConfig) (bool, []evm.StructLog, error) {
	// Validate and reprocess the block
	var (
		blockchain = api.hpb.BlockChain()
		validator  = blockchain.Validator()
		processor  = blockchain.Processor()
	)

	structLogger := evm.NewStructLogger(logConfig)

	if err := api.hpb.Hpbengine.VerifyHeader(blockchain, block.Header(), true, config.FastSync); err != nil {
		return false, structLogger.StructLogs(), err
	}
	statedb, err := blockchain.StateAt(blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1).Root())
	if err != nil {
		return false, structLogger.StructLogs(), err
	}

	receipts, _, usedGas, err := processor.Process(block, statedb)
	if err != nil {
		return false, structLogger.StructLogs(), err
	}
	if err := validator.ValidateState(block, blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1), statedb, receipts, usedGas); err != nil {
		return false, structLogger.StructLogs(), err
	}
	return true, structLogger.StructLogs(), nil
}

// formatError formats a Go error into either an empty string or the data content
// of the error itself.
func formatError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type timeoutError struct{}

func (t *timeoutError) Error() string {
	return "Execution time exceeded"
}

/*// TraceTransaction returns the structured logs created during the execution of EVM
// and returns them as a JSON object.
func (api *PrivateDebugAPI) TraceTransaction(ctx context.Context, txHash common.Hash, config *TraceArgs) (interface{}, error) {
	var tracer evm.Tracer
	if config != nil && config.Tracer != nil {
		timeout := defaultTraceTimeout
		if config.Timeout != nil {
			var err error
			if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
				return nil, err
			}
		}

		var err error
		if tracer, err = hpbapi.NewJavascriptTracer(*config.Tracer); err != nil {
			return nil, err
		}

		// Handle timeouts and RPC cancellations
		deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
		go func() {
			<-deadlineCtx.Done()
			tracer.(*hpbapi.JavascriptTracer).Stop(&timeoutError{})
		}()
		defer cancel()
	} else if config == nil {
		tracer = evm.NewStructLogger(nil)
	} else {
		tracer = evm.NewStructLogger(config.LogConfig)
	}

	// Retrieve the tx from the chain and the containing block
	tx, blockHash, _, txIndex := bc.GetTransaction(api.hpb.ChainDb(), txHash)
	if tx == nil {
		return nil, fmt.Errorf("transaction %x not found", txHash)
	}
	msg, context, statedb, err := api.computeTxEnv(blockHash, int(txIndex))
	if err != nil {
		return nil, err
	}

	// Run the transaction with tracing enabled.
	vmenv := evm.NewEVM(context, statedb, api.config, evm.Config{Debug: true, Tracer: tracer})

	block := bc.InstanceBlockChain()
	ret, gas, failed, err := bc.ApplyMessage(block, nil, nil, nil, msg , nil)
	if err != nil {
		return nil, fmt.Errorf("tracing failed: %v", err)
	}
	switch tracer := tracer.(type) {
	case *evm.StructLogger:
		return &hpbapi.ExecutionResult{
			Gas:         gas,
			Failed:      failed,
			ReturnValue: fmt.Sprintf("%x", ret),
			StructLogs:  hpbapi.FormatLogs(tracer.StructLogs()),
		}, nil
	case *hpbapi.JavascriptTracer:
		return tracer.GetResult()
	default:
		panic(fmt.Sprintf("bad tracer type %T", tracer))
	}
}*/
/*
// computeTxEnv returns the execution environment of a certain transaction.
func (api *PrivateDebugAPI) computeTxEnv(blockHash common.Hash, txIndex int) (bc.Message, evm.Context, *state.StateDB, error) {
	// Create the parent state.
	block := api.hpb.BlockChain().GetBlockByHash(blockHash)
	if block == nil {
		return nil, evm.Context{}, nil, fmt.Errorf("block %x not found", blockHash)
	}
	parent := api.hpb.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, evm.Context{}, nil, fmt.Errorf("block parent %x not found", block.ParentHash())
	}
	statedb, err := api.hpb.BlockChain().StateAt(parent.Root())
	if err != nil {
		return nil, evm.Context{}, nil, err
	}
	txs := block.Transactions()

	// Recompute transactions up to the target index.
	signer := types.MakeSigner(api.config, block.Number())
	for idx, tx := range txs {
		// Assemble the transaction call message
		msg, _ := tx.AsMessage(signer)
		context := hvm.NewEVMContext(msg, block.Header(), api.hpb.BlockChain(), nil)
		if idx == txIndex {
			return msg, context, statedb, nil
		}

		vmenv := evm.NewEVM(context, statedb, api.config, evm.Config{})
		gp := new(bc.GasPool).AddGas(tx.Gas())
		_, _, _, err := bc.ApplyMessage(vmenv, msg, gp)
		if err != nil {
			return nil, evm.Context{}, nil, fmt.Errorf("tx %x failed: %v", tx.Hash(), err)
		}
		statedb.DeleteSuicides()
	}
	return nil, evm.Context{}, nil, fmt.Errorf("tx index %d out of range for block %x", txIndex, blockHash)
}
*/
// Preimage is a debug API function that returns the preimage for a sha3 hash, if known.
func (api *PrivateDebugAPI) Preimage(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	db := bc.PreimageTable(api.hpb.ChainDb())
	return db.Get(hash.Bytes())
}

// GetBadBLocks returns a list of the last 'bad blocks' that the client has seen on the network
// and returns them as a JSON list of block-hashes
func (api *PrivateDebugAPI) GetBadBlocks(ctx context.Context) ([]bc.BadBlockArgs, error) {
	return api.hpb.BlockChain().BadBlocks()
}

// StorageRangeResult is the result of a debug_storageRangeAt API call.
type StorageRangeResult struct {
	Storage storageMap   `json:"storage"`
	NextKey *common.Hash `json:"nextKey"` // nil if Storage includes the last key in the trie.
}

type storageMap map[common.Hash]storageEntry

type storageEntry struct {
	Key   *common.Hash `json:"key"`
	Value common.Hash  `json:"value"`
}

/*
// StorageRangeAt returns the storage at the given block height and transaction index.
func (api *PrivateDebugAPI) StorageRangeAt(ctx context.Context, blockHash common.Hash, txIndex int, contractAddress common.Address, keyStart hexutil.Bytes, maxResult int) (StorageRangeResult, error) {
	_, _, statedb, err := api.computeTxEnv(blockHash, txIndex)
	if err != nil {
		return StorageRangeResult{}, err
	}
	st := statedb.StorageTrie(contractAddress)
	if st == nil {
		return StorageRangeResult{}, fmt.Errorf("account %x doesn't exist", contractAddress)
	}
	return storageRangeAt(st, keyStart, maxResult), nil
}
*/
func storageRangeAt(st state.Trie, start []byte, maxResult int) StorageRangeResult {
	it := trie.NewIterator(st.NodeIterator(start))
	result := StorageRangeResult{Storage: storageMap{}}
	for i := 0; i < maxResult && it.Next(); i++ {
		e := storageEntry{Value: common.BytesToHash(it.Value)}
		if preimage := st.GetKey(it.Key); preimage != nil {
			preimage := common.BytesToHash(preimage)
			e.Key = &preimage
		}
		result.Storage[common.BytesToHash(it.Key)] = e
	}
	// Add the 'next key' so clients can continue downloading.
	if it.Next() {
		next := common.BytesToHash(it.Key)
		result.NextKey = &next
	}
	return result
}

// PublicAdminAPI is the collection of administrative API methods exposed over
// both secure and unsecure RPC channels.
type PublicAdminAPI struct {
	node *Node // Node interfaced by this API
}

// NewPublicAdminAPI creates a new API definition for the public admin methods
// of the node itself.
func NewPublicAdminAPI(node *Node) *PublicAdminAPI {
	return &PublicAdminAPI{node: node}
}

// Peers retrieves all the information we know about each individual peer at the
// protocol granularity.
func (api *PublicAdminAPI) Peers() ([]*p2p.PeerInfo, error) {
	pm := api.node.Hpbpeermanager
	if pm == nil {
		return nil, ErrNodeStopped
	}
	return pm.PeersInfo(), nil
}

// NodeInfo retrieves all the information we know about the host node at the
// protocol granularity.
func (api *PublicAdminAPI) NodeInfo() (*p2p.NodeInfo, error) {
	pm := api.node.Hpbpeermanager
	if pm == nil {
		return nil, ErrNodeStopped
	}
	return pm.NodeInfo(), nil
}

// Datadir retrieves the current data directory the node is using.
func (api *PublicAdminAPI) Datadir() string {
	return api.node.DataDir()
}

// PublicWeb3API offers helper utils
type PublicWeb3API struct {
	stack *Node
}

// NewPublicWeb3API creates a new Web3Service instance
func NewPublicWeb3API(stack *Node) *PublicWeb3API {
	return &PublicWeb3API{stack}
}

// ClientVersion returns the node name
func (s *PublicWeb3API) ClientVersion() string {
	return config.GetHpbConfigInstance().Network.Name
}

// Sha3 applies the hpb sha3 implementation on the input.
// It assumes the input is hex encoded.
func (s *PublicWeb3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}

func createbackdatabase(num uint64) (*hpbdb.LDBDatabase, string, error) {
	log.Warn("createbakdatabase")
	dbpath, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	name := string("bakupdatabase") + strconv.FormatUint(num, 10)
	dbpath = filepath.Join(dbpath, name)

	log.Warn("database", "dbpath", dbpath)

	//os.RemoveAll(dbpath)
	db, err := hpbdb.NewLDBDatabase(dbpath, 0, 0)
	return db, dbpath, err
}

/*
func getoldbackdatabase(num uint64) (*hpbdb.LDBDatabase, string, error) {
	log.Error("createbakdatabase")
	dbpath, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	oldname := string("bakupdatabase") + strconv.FormatUint(num-uint64(20000), 10)
	oldpath := filepath.Join(dbpath, oldname)
	os.RemoveAll(oldpath)

	name := string("bakupdatabase") + strconv.FormatUint(num, 10)
	dbpath = filepath.Join(dbpath, name)

	db, err := hpbdb.NewLDBDatabase(dbpath, 0, 0)
	log.Error("database", "dbpath", dbpath, "err", err)

	return db, dbpath, err
}
*/
func getstatedb(blockchain *bc.BlockChain, num uint64) (*hpbdb.LDBDatabase, common.Hash, error) {
	log.Error("getstatedb")
	if num > blockchain.CurrentBlock().Number().Uint64()-uint64(mindistance) {
		return nil, common.Hash{}, errors.New("Get Statedb Error")
	}
	block := blockchain.GetBlockByNumber(num)
	if block == nil {
		return nil, common.Hash{}, errors.New("Get Statedb Block Error")
	}
	root := block.Root()
	log.Warn("getstatedb", "root", root)
	return db.GetHpbDbInstance(), root, nil
}

/*
func backupstatedata(backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, root common.Hash, num uint64) error {
	log.Error("bakupstatedata")
	statetrie := state.NewStateSync(root, backupdb)
	log.Warn("bakupstatedata", "lenrequests", statetrie.Pending())
	olddb, _, olderr := getoldbackdatabase(num - uint64(20000))
	if olderr != nil || olddb == nil {
		olddb = backupdb
	}
	for statetrie.Pending() > 0 {
		requests := statetrie.Missing(16) //max len(requests) = 16

		for _, item := range requests {
			entry, err := olddb.Get(item.Bytes())
			if err != nil {
				entry, err = hpbdb.Get(item.Bytes())
				if err != nil {
					log.Error("backupstatedata", "get item err try again in 300s", err, "item", common.Bytes2Hex(item.Bytes()))
					time.Sleep(300 * time.Second)
					entry, err = hpbdb.Get(item.Bytes())
					if err != nil {
						log.Error("backupstatedata", "get item err", err)
						return err
					}
				}
			}

			log.Warn("backupstatedata", "root", item)
			res := trie.SyncResult{Data: entry}
			kecc := sha3.NewKeccak256()
			kecc.Reset()
			kecc.Write(entry)
			kecc.Sum(res.Hash[:0])
			_, _, err = statetrie.ReduceProcess([]trie.SyncResult{res})
			if err != nil {
				log.Error("backupstatedata", "ProcessResponse error", err)
				return err
			}
			//hpbdb.Delete(item.Bytes())
		}
		b := backupdb.NewBatch()
		statetrie.Commit(b)
		if err := b.Write(); err != nil {
			log.Error("BackupDB write", "error", err)
			return err
		}
	}

	return nil
}
*/
/*
func delstatedata(blockchain *bc.BlockChain, backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, num uint64) error {
	log.Error("delstatedata")
	errnum := 0
	var errs error
	for i := num - 1; i > 0; i-- {
		block := blockchain.GetBlockByNumber(i)
		if block == nil {
			log.Error("delstatedata Canot find block", "num", i)
			break
		}
		root := block.Root()
		_, errs = blockchain.StateAt(root)
		if errs != nil {
			errnum = errnum + 1
			if errnum > 100 {
				break
			}
			log.Error("delstatedata Canot get State", "num", i)
			continue
		}
		statetrie := state.NewStateSync(root, backupdb)

		log.Warn("delstatedata", "num", i, "pending", statetrie.Pending())
		for statetrie.Pending() > 0 && errs == nil {
			requests := statetrie.Missing(16) //max len(requests) = 16
			for _, item := range requests {
				_, err := backupdb.Get(item.Bytes())
				if err == nil {
					continue
				}
				entry, err := hpbdb.Get(item.Bytes())
				if err != nil {
					errs = err
					continue
				}
				log.Debug("delstatedata", "root", item, "entry", common.Bytes2Hex(entry))
				res := trie.SyncResult{Data: entry}
				kecc := sha3.NewKeccak256()
				kecc.Reset()
				kecc.Write(entry)
				kecc.Sum(res.Hash[:0])
				_, _, err = statetrie.ReduceProcess([]trie.SyncResult{res})
				if err != nil {
					log.Error("delstatedata", "ProcessResponse error", err)
					errs = err
				}
				hpbdb.Delete(item.Bytes())
			}
		}
	}
	return errs
}
*/
func recoverstatedata(backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, root common.Hash, num uint64) error {
	log.Error("recover")

	hpbdb.Delete(root.Bytes()) //避免hpbdb存在root，导致无法恢复
	statetrie := state.NewStateSyncToreduce(root, hpbdb)
	log.Warn("recover", "lenrequests", statetrie.Pending())

	for statetrie.Pending() > 0 {
		requests := statetrie.Missing(16) //max len(requests) = 16
		for _, item := range requests {
			entry, err := backupdb.Get(item.Bytes())
			if err != nil {
				log.Error("recover", "get item err", err)
				return err
			}
			//hpbdb.Delete(item.Bytes()) //避免备份过程中，有状态合并到新文件中，导致无法恢复
			log.Warn("recoverstatedata", "root", item)
			res := trie.SyncResult{Data: entry}
			kecc := sha3.NewKeccak256()
			kecc.Reset()
			kecc.Write(entry)
			kecc.Sum(res.Hash[:0])
			_, _, err = statetrie.ReduceProcess([]trie.SyncResult{res})
			if err != nil {
				log.Error("recover", "ProcessResponse error", err)
				return err
			}
		}
		b := hpbdb.NewBatch()
		statetrie.Commit(b)
		if err := b.Write(); err != nil {
			log.Error("BackupDB write", "error", err)
			return err
		}
	}
	return nil
}

/*
func delbackupstatedb(dbpath string) {
	log.Error("delbakupstatedb")
	//os.RemoveAll(dbpath)
}
*/
/*
func (api *PublicHpbAPI) DelStateDatabyNum(num *rpc.BlockNumber) bool {
	go func() {

		skip := uint64(*num) / uint64(20000)
		for skip < 200 {
			time.Sleep(10 * time.Second)
			if api.e.BlockChain().CurrentBlock().Number().Uint64() > uint64(20000)*skip {
				//blocknum := uint64(20000) * skip
				blocknum := api.e.BlockChain().CurrentBlock().Number().Uint64() / uint64(20000) * uint64(20000)
				skip++

				log.Error("DelStateDatabyNum", "num", *num, "blocknum", blocknum)
				//getstatedb
				hpbdb, root, err := getstatedb(api.e.BlockChain(), blocknum)
				if err != nil {
					log.Error("Get statedb ", "Error", err)
					continue
				}
				backupdb, dbpath, err := createbackdatabase(blocknum)
				if err != nil {
					log.Error("Create Bakupdatabase ", "Error", err)
					continue
				}
				err = backupstatedata(backupdb, hpbdb, root, blocknum)
				if err != nil {
					recoverstatedata(backupdb, hpbdb, root, blocknum)
					continue
				}
				err = delstatedata(api.e.BlockChain(), backupdb, hpbdb, blocknum)
				if err != nil {
					recoverstatedata(backupdb, hpbdb, root, blocknum)
					continue
				}
				recoverstatedata(backupdb, hpbdb, root, blocknum)
				delbackupstatedb(dbpath)
			}
		}
	}()

	return true
}
*/
/*
func modifydb(hpbpath string, newdbpath string) {

	hpbpath = hpbpath + "/ghpb/chaindata"
	bakupdb := hpbpath + "bak"
	log.Warn("modifydb", "hpbpath", hpbpath)
	log.Warn("modifydb", "newdbpath", newdbpath)
	log.Warn("modifydb", "bakupdb", bakupdb)
	err := os.Rename(hpbpath, bakupdb)
	if err != nil {
		log.Error("bakupdb err", "err", err)
		return
	}
	err = os.Rename(newdbpath, hpbpath)
	if err != nil {
		log.Error("move db err", "err", err)
		return
	}
	err = os.RemoveAll(bakupdb)
	if err != nil {
		log.Error("removedb err", "err", err)
		return
	}
	err = os.RemoveAll(newdbpath)
	if err != nil {
		log.Error("removedb err", "err", err)
		return
	}
}
*/
func backupStateData(backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, root common.Hash, num uint64) error {
	log.Error("bakupstatedata")
	statetrie := state.NewStateSync(root, backupdb)
	//hpbdb.Delete(root.Bytes())
	log.Warn("bakupstatedata", "lenrequests", statetrie.Pending(), "num", num)
	for statetrie.Pending() > 0 {
		requests := statetrie.Missing(16) //max len(requests) = 16
		for _, item := range requests {
			entry, err := hpbdb.Get(item.Bytes())
			if err != nil {
				log.Error("backupstatedata", "get item err try again in 60s", err, "item", common.Bytes2Hex(item.Bytes()))
				for i := 0; i < 10; i++ {
					time.Sleep(60 * time.Second)
					entry, err = hpbdb.Get(item.Bytes())
					if err == nil {
						break
					}
				}
				if err != nil {
					log.Error("backupStateData", "err", err)
					return err
				}
			}

			log.Warn("backupstatedata", "root", item)
			res := trie.SyncResult{Data: entry}
			kecc := sha3.NewKeccak256()
			kecc.Reset()
			kecc.Write(entry)
			kecc.Sum(res.Hash[:0])
			_, _, err = statetrie.ReduceProcess([]trie.SyncResult{res})
			if err != nil {
				log.Error("backupstatedata", "ProcessResponse error", err)
				return err
			}
			//hpbdb.Delete(item.Bytes()) //删除会导致同步停止，考虑到reduce的时间长，还不如重新快速同步呢，因此这里的删除还是有问题。
		}
		b := backupdb.NewBatch()
		statetrie.Commit(b)
		if err := b.Write(); err != nil {
			log.Error("BackupDB write", "error", err)
			return err
		}
	}

	return nil
}

func recoverInsertBlock(blockchain *bc.BlockChain, newblockchain *bc.BlockChain, backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, blocknum uint64, blockheight uint64) error {
	var err error
	for i := uint64(0); i <= blockheight; i++ {
		blocks := make([]*types.Block, 1)
		block := newblockchain.GetBlockByNumber(i)
		blocks[0] = block
		bc.WriteCanonicalHash(hpbdb, block.Hash(), block.Number().Uint64())
		bc.WriteHeader(hpbdb, block.Header())
		if i <= blocknum {
			receipts := make([]types.Receipts, 1)
			receipts[0] = bc.GetBlockReceipts(backupdb, block.Hash(), i)
			td := bc.GetTd(backupdb, block.Hash(), block.Number().Uint64())
			bc.WriteTd(hpbdb, block.Hash(), block.Number().Uint64(), td)
			_, err = blockchain.InsertReceiptChain(blocks, receipts)
			if err != nil {
				log.Error("reducedbrecover InsertReceiptChain", "err", err)
				break
			}
			if i == blocknum-pivotsynfull {
				break
			}
			if 0 == i {
				recoverstatedata(backupdb, hpbdb, block.Root(), 0)
				i = blocknum - pivotsynfull //insert lastet  pivotsynfull blocks ,then insert from 1 to block-pivotsynfull blocks
			}
			if i == blocknum {
				err = recoverstatedata(backupdb, hpbdb, block.Root(), blocknum)
				if err == nil {
					blockchain.FastSyncCommitHead(block.Hash())
				} else {
					log.Error("recoverstatedata", "err", err)
					log.Error("syncfast")
					break
				}
			}
		} else {
			log.Info("reducedbrecover", "insert", i)
			_, err = blockchain.InsertChainToWriteState(blocks)
			if err != nil {
				log.Error("reducedbrecover InsertChainToWriteState", "err", err)
				break
			}
			blockchain.SetCurrentBlock(block)
			if i == blockheight {
				for j := blockheight + 1; ; j++ {
					bs := make([]*types.Block, 1)
					latestblock := blockchain.GetBlockByNumber(j)
					if nil == latestblock {
						break
					}
					bs[0] = latestblock
					_, err = blockchain.InsertChainToWriteState(bs)
					if err != nil {
						break
					}
					blockchain.SetCurrentBlock(latestblock)
				}
				i = 0
			}
		}
	}
	return err
}

func BackupBlocks(blockchain *bc.BlockChain, newblockchain *bc.BlockChain, backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, blocknum uint64, blockheight uint64) error {
	var err error
	ierrtimes := 0
	for i := uint64(1); i <= blockheight; i++ {
		blocks := make([]*types.Block, 1)
		block := blockchain.GetBlockByNumber(i)
		blocks[0] = block
		//bc.WriteCanonicalHash(backupdb,block.Hash(),block.Number().Uint64())
		//bc.WriteHeader(backupdb,block.Header())
		newblockchain.WriteHeader(block.Header())
		log.Info("InsertReceiptChain", "num", block.Number().Uint64(), "hash", newblockchain.GetHeaderByNumber(i).Hash())

		if i <= blocknum {
			receipts := make([]types.Receipts, 1)
			receipts[0] = bc.GetBlockReceipts(hpbdb, block.Hash(), i)
			td := bc.GetTd(hpbdb, block.Hash(), block.Number().Uint64())
			bc.WriteTd(backupdb, block.Hash(), block.Number().Uint64(), td)
			_, err = newblockchain.InsertReceiptChain(blocks, receipts)
			if err != nil {
				log.Error("reducedbbak receipt", "err", err, "blocknum", i)
				if ierrtimes < 10 {
					ierrtimes++
					i--
				} else {
					return err
				}
			}
			if i == blocknum {
				newblockchain.FastSyncCommitHead(block.Hash())
			}
		} else {
			log.Info("reducedbbak", "insert", i)
			_, err = newblockchain.InsertChain(blocks)
			if err != nil {
				log.Error("reducedbbak insert", "err", err)
				if ierrtimes < 10 {
					ierrtimes++
					i--
				} else {
					return err
				}
			}
		}
	}
	return nil
}

func BackupBlocksAsyn(blockchain *bc.BlockChain, newblockchain *bc.BlockChain, backupdb *hpbdb.LDBDatabase, hpbdb *hpbdb.LDBDatabase, blocknum uint64, blockheight uint64) error {
	var err error
	blockqueue := make(chan *types.Block, 4096)
	go func() {
		for i := uint64(1); i <= blockheight; i++ {
			block := blockchain.GetBlockByNumber(i)
			blockqueue <- block
		}
	}()

	for {
		select {
		case block, ok := <-blockqueue:
			if !ok {
				log.Error("blockqueue error")
				return nil
			}
			blocks := make([]*types.Block, 1)
			blocks[0] = block

			newblockchain.WriteHeader(block.Header())

			num := block.Number().Uint64()
			if num <= blocknum {
				log.Info("InsertReceiptChain", "insert", num)
				receipts := make([]types.Receipts, 1)
				receipts[0] = bc.GetBlockReceipts(hpbdb, block.Hash(), num)
				td := bc.GetTd(hpbdb, block.Hash(), block.Number().Uint64())
				bc.WriteTd(backupdb, block.Hash(), block.Number().Uint64(), td)
				_, err = newblockchain.InsertReceiptChain(blocks, receipts)
				if err != nil {
					log.Error("InsertReceiptChain", "err", err)
					return err
				}
				if num == blocknum {
					newblockchain.FastSyncCommitHead(block.Hash())
				}
			} else {
				log.Info("reducedbbak", "insert", num)
				_, err = newblockchain.InsertChain(blocks)
				if err != nil {
					log.Error("reducedbbak insert", "err", err)
					return err
				}
				if block.Number().Uint64() == blockheight {
					return nil
				}
			}

		}
	}
}

func (api *PublicHpbAPI) Reducedb() {
	go func() {
		blockchain := api.e.BlockChain()
		blocknum := blockchain.CurrentBlock().Number().Uint64() - uint64(pivotsynfull)
		if blocknum < uint64(pivotsynfull) {
			log.Error("reducedb height too low")
			return
		}

		hpbdb, root, err := getstatedb(blockchain, blocknum)
		if err != nil {
			log.Error("reducedb Get statedb ", "Error", err)
			return
		}
		//delMaxnum := hpbdb.GetFdNum()
		//log.Warn("reducedb ", "fdnum", delMaxnum)
		backupdb, bakpath, err := createbackdatabase(blocknum)
		log.Warn("reducedb bakpath", "bakpath", bakpath)
		if err != nil {
			log.Error("Create Bakupdatabase ", "Error", err)
			return
		}
		gensisblock := blockchain.GetBlockByNumber(0)
		bc.WriteCanonicalHash(backupdb, gensisblock.Hash(), gensisblock.Number().Uint64())
		bc.WriteHeader(backupdb, gensisblock.Header())
		bc.WriteBody(backupdb, gensisblock.Hash(), gensisblock.Number().Uint64(), gensisblock.Body())
		td := bc.GetTd(hpbdb, gensisblock.Hash(), 0)
		bc.WriteTd(backupdb, gensisblock.Hash(), 0, td)
		log.Warn("reducedb gensisi root", "gensisroot", gensisblock.Root())
		err = backupStateData(backupdb, hpbdb, gensisblock.Root(), 0)
		if err != nil {
			log.Error("backupstatedata000 ", "Error", err)
			return
		}
		log.Warn("reducedb write NewBlockChainWithEngine")

		newblockchain, _ := bc.NewBlockChainWithEngine(backupdb, &config.GetHpbConfigInstance().BlockChain, prometheus.InstancePrometheus())

		log.Warn("reducedb write backup statedata")

		err = backupStateData(backupdb, hpbdb, root, blocknum)
		if err != nil {
			log.Error("reducedb backupstatedata ", "Error", err)
			return
		}
		blockheight := blockchain.CurrentBlock().Number().Uint64()

		log.Warn("reducedb backup blocks", "blockheight", blockheight, "blocknum", blocknum)
		err = BackupBlocks(blockchain, newblockchain, backupdb, hpbdb, blocknum, blockheight)
		if err != nil {
			log.Error("BackupBlocks error")
			return
		}
		/*
			for i := uint64(1); i <= blockheight; i++ {
				blocks := make([]*types.Block, 1)
				block := blockchain.GetBlockByNumber(i)
				blocks[0] = block
				//bc.WriteCanonicalHash(backupdb,block.Hash(),block.Number().Uint64())
				//bc.WriteHeader(backupdb,block.Header())
				newblockchain.WriteHeader(block.Header())
				log.Info("InsertReceiptChain", "num", block.Number().Uint64(), "hash", newblockchain.GetHeaderByNumber(i).Hash())

				if i <= blocknum {
					receipts := make([]types.Receipts, 1)
					receipts[0] = bc.GetBlockReceipts(hpbdb, block.Hash(), i)
					td := bc.GetTd(hpbdb, block.Hash(), block.Number().Uint64())
					bc.WriteTd(backupdb, block.Hash(), block.Number().Uint64(), td)
					_, err = newblockchain.InsertReceiptChain(blocks, receipts)
					if err != nil {
						log.Error("reducedbbak receipt", "err", err, "blocknum", i)
						if ierrtimes < 10 {
							ierrtimes++
							i--
						} else {
							return
						}
					}
					if i == blocknum {
						newblockchain.FastSyncCommitHead(block.Hash())
					}
				} else {
					log.Info("reducedbbak", "insert", i)
					_, err = newblockchain.InsertChain(blocks)
					if err != nil {
						log.Error("reducedbbak insert", "err", err)
						if ierrtimes < 10 {
							ierrtimes++
							i--
						} else {
							return
						}
					}
				}
			}
		*/
		delMaxnum := hpbdb.GetFdNum() - int64(100) //为了不影响新区块的同步，保留最近100个文件
		log.Warn("reducedb ", "fdnum", delMaxnum)

		log.Warn("reducedb DeleteFiles")
		hpbdb.DeleteFiles(delMaxnum)
		log.Warn("reducedb RecoverBlocks and statedb")
		err = recoverInsertBlock(blockchain, newblockchain, backupdb, hpbdb, blocknum, blockheight)
		/*
			for i := uint64(0); i <= blockheight; i++ {
				blocks := make([]*types.Block, 1)
				block := newblockchain.GetBlockByNumber(i)
				blocks[0] = block
				bc.WriteCanonicalHash(hpbdb, block.Hash(), block.Number().Uint64())
				bc.WriteHeader(hpbdb, block.Header())
				if i <= blocknum {
					receipts := make([]types.Receipts, 1)
					receipts[0] = bc.GetBlockReceipts(backupdb, block.Hash(), i)
					td := bc.GetTd(backupdb, block.Hash(), block.Number().Uint64())
					bc.WriteTd(hpbdb, block.Hash(), block.Number().Uint64(), td)
					_, err = blockchain.InsertReceiptChain(blocks, receipts)
					if err != nil {
						log.Error("reducedbrecover", "err", err)
						break
					}
					if i == blocknum {
						recoverstatedata(backupdb, hpbdb, gensisblock.Root(), 0)
						err = recoverstatedata(backupdb, hpbdb, root, blocknum)
						if err == nil {
							blockchain.FastSyncCommitHead(block.Hash())
						} else {
							log.Error("recoverstatedata", "err", err)
							log.Error("syncfast")
							break
						}
					}
				} else {
					log.Info("reducedbrecover", "insert", i)
					_, err = blockchain.InsertChainToWriteState(blocks)
					if err != nil {
						log.Error("reducedbrecover", "err", err)
						break
					}
					if i == blockheight {
						blockchain.SetCurrentBlock(block)
					}
				}
			}
		*/
		/*
			if nil == err {
				log.Warn("reducedb Recover latest")
				for i := blockheight + 1; ; i++ {
					blocks := make([]*types.Block, 1)
					block := blockchain.GetBlockByNumber(i)
					if nil == block {
						break
					}
					blocks[0] = block
					_, err = blockchain.InsertChainToWriteState(blocks)
					if err != nil {
						break
					}
					blockchain.SetCurrentBlock(block)
				}
			}*/
		os.RemoveAll(bakpath)
		//api.e.Hpbpeermanager.DropPeers()
		log.Error("ENDDDDDDDDDDDDDDD")
	}()
}

/*
func (api *PublicHpbAPI) WriteBlockState(blockNum uint64) string {
	log.Error("WriteBlockState   WriteBlockState  WriteBlockState", "blockNum", blockNum)
	if blockNum == 0 {
		return string("")
	}
	blockchain := api.e.BlockChain()
	var block *types.Block
	block = blockchain.GetBlockByNumber(blockNum)
	if block == nil {
		return string("getblockerror")
	}
	//parentblock := blockchain.GetBlockByNumber(blockNum - 1)
	//if block == nil {
	//	return string("getblockerror")
	//}
	blocks := make([]*types.Block, 0)
	//blocks = append(blocks, parentblock)
	blocks = append(blocks, block)
	if _, err := blockchain.InsertChainToWriteState(blocks); err != nil {
		log.Error("invalid hash chain(fast->WriteBlockState)", "err", err)
		return string("error")
	}
	return string("")
}*/
/*
func writeblockbydb(hpbdb *hpbdb.LDBDatabase, block *types.Block) {
	bc.WriteCanonicalHash(hpbdb, block.Hash(), block.Number().Uint64())
	bc.WriteHeader(hpbdb, block.Header())
	bc.WriteBody(hpbdb, block.Hash(), block.Number().Uint64(), block.Body())
	td := bc.GetTd(hpbdb, block.Hash(), block.Number().Uint64())
	bc.WriteTd(hpbdb, block.Hash(), block.Number().Uint64(), td)
}*/

/*
func deleteldb(path string, maxnum int64) {
	hpbpattern := path + "/ghpb/chaindata/*.ldb"
	matchfiles, err := filepath.Glob(hpbpattern)
	if err != nil {
		log.Error("deleteldb", "err", err, "pattern", hpbpattern)
		return
	}
	for _, file := range matchfiles {
		basefile := filepath.Base(file)
		fdnum, err := strconv.ParseInt(basefile[:len(basefile)-len(".ldb")], 10, 64)
		if err != nil {
			continue
		}
		if fdnum < maxnum-10 { //forward 10 to just in case
			log.Warn("remove", "ldbname", file, "base", filepath.Base(file))
			os.Remove(file)
		}
	}
}
*/
/*
func (api *PublicHpbAPI) Deletestatedb() {
	go func() {
		blockchain := api.e.BlockChain()
		blocknum := blockchain.CurrentBlock().Number().Uint64() - uint64(pivotsynfull)
		if blocknum < uint64(pivotsynfull) {
			log.Error("height too low")
			return
		}
		hpbdb, root, err := getstatedb(blockchain, blocknum)
		if err != nil {
			log.Error("Get statedb ", "Error", err)
			return
		}
		delMaxnum := hpbdb.GetFdNum()
		log.Error("11111111111111", "fdnum", delMaxnum)
		backupdb, dbpath, err := createbackdatabase(blocknum)
		if err != nil {
			log.Error("Create Bakupdatabase ", "path", dbpath, "Error", err)
			return
		}
		gensisblock := blockchain.GetBlockByNumber(0)
		writeblockbydb(hpbdb, gensisblock)
		log.Warn("gensisi root", "gensisroot", gensisblock.Root())
		err = backupStateData(backupdb, hpbdb, gensisblock.Root(), 0)
		if err != nil {
			log.Error("backupstatedata000 ", "Error", err)
			return
		}
		log.Error("write backupstatedata")
		err = backupStateData(backupdb, hpbdb, root, blocknum)
		if err != nil {
			log.Error("backupstatedata ", "Error", err)
			return
		}
		blockheight := blockchain.CurrentBlock().Number().Uint64()
		log.Warn("Deletestatedb", "blockheight", blockheight)
		for i := uint64(1); i <= blockheight; i++ {
			log.Warn("Deletestatedb", "block", i, "pivot", blocknum)
			blocks := make([]*types.Block, 1)
			block := blockchain.GetBlockByNumber(i)
			blocks[0] = block
			writeblockbydb(hpbdb, block)
			if i <= blocknum {
				receipts := make([]types.Receipts, 1)
				receipts[0] = bc.GetBlockReceipts(hpbdb, block.Hash(), i)
				_, err := blockchain.InsertReceiptChain(blocks, receipts)
				if err != nil {
					log.Error("err", "err", err)
					return
				}
				if i == blocknum {
					//recoverstatedata(backupdb, hpbdb, gensisblock.Root(), 0)
					//recoverstatedata(backupdb, hpbdb, root, blocknum)
					blockchain.FastSyncCommitHead(block.Hash())
				}
			} else {
				log.Warn("Deletestatedb", "insert", i)

				_, err := blockchain.InsertChainToWriteState(blocks)
				if err != nil {
					log.Error("err", "err", err)
					return
				}
			}
		}
		//deleteldb(api.e.DataDir(),delMaxnum)
		log.Error("11111111111111", "fdnum", delMaxnum)
		hpbdb.DeleteFiles(delMaxnum)
	}()
}
*/
