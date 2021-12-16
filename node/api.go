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
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/hpb-project/go-hpb/network/p2p/discover"

	bc "github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/common/trie"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/rpc"
)

const defaultHashlen = 66

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

func (api *PublicHpbAPI) GetRandom(blocknum *rpc.BlockNumber) string {
	blockchain := api.e.BlockChain()
	var header *types.Header
	if blocknum == nil || *blocknum == rpc.LatestBlockNumber {
		header = blockchain.CurrentHeader()
	} else {
		log.Debug("getRandom", "num", blocknum.Int64())
		header = blockchain.GetHeaderByNumber(uint64(blocknum.Int64()))
	}
	if header != nil {
		extra := header.ExtraRandom()
		return common.ToHex(extra)
	}
	return ""
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
		gp            = new(bc.GasPool).AddGas(block.GasLimit().Uint64())
		header        = block.Header()
		totalUsedGas  = big.NewInt(0)
		allAddress    = make(map[common.Address]*big.Int)
		allState_Diff = []StateDiff{}
	)

	for i, tx := range block.Transactions() {
		state_diff := StateDiff{txhash: tx.Hash()}
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		if (tx.To() == nil || len(statedb.GetCode(*tx.To())) > 0) && len(tx.Data()) > 0 {
			evmstatediff, _, _, err := bc.ApplyTransaction(blockchain.Config(), blockchain, nil, gp, statedb, header, tx, totalUsedGas)
			log.Debug("evmdiff", "evmstatediff", evmstatediff, "err", err)
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
		gp            = new(bc.GasPool).AddGas(block.GasLimit().Uint64())
		header        = block.Header()
		totalUsedGas  = big.NewInt(0)
		allAddress    = make(map[common.Address]*big.Int)
		allState_Diff = []StateDiff{}
	)

	for i, tx := range block.Transactions() {
		state_diff := StateDiff{txhash: tx.Hash()}
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		if (tx.To() == nil || len(statedb.GetCode(*tx.To())) > 0) && len(tx.Data()) > 0 {
			evmstatediff, _, _, err := bc.ApplyTransaction(blockchain.Config(), blockchain, nil, gp, statedb, header, tx, totalUsedGas)
			log.Debug("evmdiff", "evmstatediff", evmstatediff, "err", err)
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

func (api *PrivateAdminAPI) AddPeer(url string) error {
	node, err := discover.ParseNode(url)
	if err != nil {
		return err
	}
	api.hpb.Hpbpeermanager.P2pSvr().AddPeer(node)
	return nil
}

func (api *PrivateAdminAPI) RemovePeer(url string) error {
	node, err := discover.ParseNode(url)
	if err != nil {
		return err
	}
	api.hpb.Hpbpeermanager.P2pSvr().RemovePeer(node)
	return nil
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
		if stateDb == nil {
			return state.Dump{}, fmt.Errorf("no pending")
		}
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

// Preimage is a debug API function that returns the preimage for a sha3 hash, if known.
func (api *PrivateDebugAPI) Preimage(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	db := bc.PreimageTable(api.hpb.ChainDb())
	return db.Get(hash.Bytes())
}

// BadBlockArgs represents the entries in the list returned when bad blocks are queried.
type BadBlockArgs struct {
	Hash   common.Hash   `json:"hash"`
	Header *types.Header `json:"header"`
}

// BadBlocks returns a list of the last 'bad blocks' that the client has seen on the network
func (api *PrivateDebugAPI) GetBadBlocks(ctx context.Context) ([]BadBlockArgs, error) {
	badblocks := api.hpb.BlockChain().BadBlocks()
	headers := make([]BadBlockArgs, len(badblocks))
	for index, block := range badblocks {
		headers[index] = BadBlockArgs{Hash: block.Hash(), Header: block.Header()}
	}
	return headers, nil
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
	return config.HpbConfigIns.Node.Version
}

// Sha3 applies the hpb sha3 implementation on the input.
// It assumes the input is hex encoded.
func (s *PublicWeb3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}
