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
	"context"
	"errors"
	"math/big"

	"github.com/hpb-project/go-hpb/vmcore"
	"github.com/hpb-project/go-hpb/vmcore/vm"

	accounts "github.com/hpb-project/go-hpb/account"
	bc "github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/bloombits"
	"github.com/hpb-project/go-hpb/blockchain/state"
	hpbdb "github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/math"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/event/sub"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/node/gasprice"
	"github.com/hpb-project/go-hpb/synctrl"
)

// HpbApiBackend implements ethapi.Backend for full nodes
type HpbApiBackend struct {
	hpb *Node
	gpo *gasprice.Oracle
}

func (b *HpbApiBackend) ChainConfig() *config.ChainConfig {
	return &b.hpb.Hpbconfig.BlockChain
}

func (b *HpbApiBackend) CurrentBlock() *types.Block {
	return b.hpb.Hpbbc.CurrentBlock()
}

func (b *HpbApiBackend) CurrentHeader() *types.Header {
	return b.hpb.Hpbbc.CurrentHeader()
}

func (b *HpbApiBackend) SetHead(number uint64) {
	b.hpb.Hpbsyncctr.Syncer().Cancel()
	b.hpb.Hpbbc.SetHead(number)
}

func (b *HpbApiBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		// block := b.hpb.miner.PendingBlock()
		// return block.Header(), nil
		return b.hpb.Hpbbc.CurrentHeader(), nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.hpb.Hpbbc.CurrentHeader(), nil
	}
	return b.hpb.Hpbbc.GetHeaderByNumber(uint64(blockNr)), nil
}

func (b *HpbApiBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.hpb.BlockChain().GetHeaderByHash(hash), nil
}

func (b *HpbApiBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		//	block := b.hpb.miner.PendingBlock()
		//	return block, nil
		return b.hpb.Hpbbc.CurrentBlock(), nil

	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.hpb.Hpbbc.CurrentBlock(), nil
	}
	return b.hpb.Hpbbc.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *HpbApiBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.hpb.BlockChain().GetBlockByHash(hash), nil
}

func (b *HpbApiBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.hpb.BlockChain().GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.hpb.BlockChain().GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block := b.hpb.BlockChain().GetBlock(hash, header.Number.Uint64())
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *HpbApiBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.hpb.BlockChain().GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.hpb.BlockChain().GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		header = b.hpb.BlockChain().GetHeader(hash, header.Number.Uint64())
		if header == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *HpbApiBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block, state := b.hpb.miner.Pending()
		if block == nil {
			return nil, nil, errors.New("no pending")
		}
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	stateDb, err := b.hpb.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *HpbApiBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.hpb.BlockChain().GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := b.hpb.BlockChain().StateAt(header.Root)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *HpbApiBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	return b.hpb.Hpbbc.GetBlockByHash(blockHash), nil
}

func (b *HpbApiBackend) GetTransaction(ctx context.Context, hash common.Hash) (*types.Transaction, common.Hash, uint64, uint64) {
	return bc.GetTransaction(b.hpb.HpbDb, hash)
}

func (b *HpbApiBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	return bc.GetBlockReceipts(b.hpb.HpbDb, blockHash, bc.GetBlockNumber(b.hpb.HpbDb, blockHash)), nil
}

func (b *HpbApiBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.hpb.Hpbbc.GetTdByHash(blockHash)
}

func (b *HpbApiBackend) GetEVM(ctx context.Context, msg types.Message, state *state.StateDB, header *types.Header) (vmcore.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }
	return vm.NewEVM(&b.hpb.Hpbconfig.BlockChain, msg, header, b.hpb.BlockChain(), nil, state), vmError, nil
}

func (b *HpbApiBackend) SubscribeRemovedLogsEvent(ch chan<- bc.RemovedLogsEvent) sub.Subscription {
	return b.hpb.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *HpbApiBackend) SubscribeChainEvent(ch chan<- bc.ChainEvent) sub.Subscription {
	return b.hpb.BlockChain().SubscribeChainEvent(ch)
}

func (b *HpbApiBackend) SubscribeChainHeadEvent(ch chan<- bc.ChainHeadEvent) sub.Subscription {
	return b.hpb.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *HpbApiBackend) SubscribeChainSideEvent(ch chan<- bc.ChainSideEvent) sub.Subscription {
	return b.hpb.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *HpbApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) sub.Subscription {
	return b.hpb.BlockChain().SubscribeLogsEvent(ch)
}

func (b *HpbApiBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.hpb.TxPool().AddTx(signedTx)
}

func (b *HpbApiBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.hpb.TxPool().Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *HpbApiBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.hpb.TxPool().GetTxByHash(hash)
}

func (b *HpbApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.hpb.TxPool().State().GetNonce(addr), nil
}

func (b *HpbApiBackend) Stats() (pending int, queued int) {
	return b.hpb.TxPool().Stats()
}

func (b *HpbApiBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.hpb.TxPool().Content()
}

func (b *HpbApiBackend) TxPoolContentFrom(addr common.Address) (types.Transactions, types.Transactions) {
	return b.hpb.TxPool().ContentFrom(addr)
}

func (b *HpbApiBackend) SubscribeTxPreEvent(ch chan<- bc.TxPreEvent) sub.Subscription {
	return b.hpb.TxPool().SubscribeTxPreEvent(ch)
}

func (b *HpbApiBackend) Downloader() *synctrl.Syncer {
	return b.hpb.Hpbsyncctr.Syncer()
}

func (b *HpbApiBackend) ProtocolVersion() int {
	return b.hpb.EthVersion()
}

func (b *HpbApiBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *HpbApiBackend) ChainDb() hpbdb.Database {
	return b.hpb.ChainDb()
}

func (b *HpbApiBackend) EventMux() *sub.TypeMux {
	return b.hpb.NewBlockMux()
}

func (b *HpbApiBackend) AccountManager() *accounts.Manager {
	return b.hpb.AccountManager()
}

func (b *HpbApiBackend) RPCGasCap() uint64 {
	return b.hpb.Hpbconfig.Node.RPCGasCap
}

func (b *HpbApiBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.hpb.bloomIndexer.Sections()
	return config.BloomBitsBlocks, sections
}

func (b *HpbApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.hpb.bloomRequests)
	}
}
