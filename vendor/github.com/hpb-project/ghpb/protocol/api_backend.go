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

package hpb

import (
	"context"
	"math/big"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/common/math"
	"github.com/hpb-project/ghpb/core"
	"github.com/hpb-project/ghpb/core/bloombits"
	"github.com/hpb-project/ghpb/core/state"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/core/vm"
	"github.com/hpb-project/ghpb/protocol/downloader"
	"github.com/hpb-project/ghpb/protocol/gasprice"
	"github.com/hpb-project/ghpb/storage"
	"github.com/hpb-project/ghpb/core/event"
	"github.com/hpb-project/ghpb/common/constant"
	"github.com/hpb-project/ghpb/network/rpc"
)

// HpbApiBackend implements ethapi.Backend for full nodes
type HpbApiBackend struct {
	hpb *Hpb
	gpo *gasprice.Oracle
}

func (b *HpbApiBackend) ChainConfig() *params.ChainConfig {
	return b.hpb.chainConfig
}

func (b *HpbApiBackend) CurrentBlock() *types.Block {
	return b.hpb.blockchain.CurrentBlock()
}

func (b *HpbApiBackend) SetHead(number uint64) {
	b.hpb.protocolManager.downloader.Cancel()
	b.hpb.blockchain.SetHead(number)
}

func (b *HpbApiBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block := b.hpb.miner.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.hpb.blockchain.CurrentBlock().Header(), nil
	}
	return b.hpb.blockchain.GetHeaderByNumber(uint64(blockNr)), nil
}

func (b *HpbApiBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block := b.hpb.miner.PendingBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return b.hpb.blockchain.CurrentBlock(), nil
	}
	return b.hpb.blockchain.GetBlockByNumber(uint64(blockNr)), nil
}

func (b *HpbApiBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block, state := b.hpb.miner.Pending()
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

func (b *HpbApiBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	return b.hpb.blockchain.GetBlockByHash(blockHash), nil
}

func (b *HpbApiBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	return core.GetBlockReceipts(b.hpb.chainDb, blockHash, core.GetBlockNumber(b.hpb.chainDb, blockHash)), nil
}

func (b *HpbApiBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.hpb.blockchain.GetTdByHash(blockHash)
}

func (b *HpbApiBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.hpb.BlockChain(), nil)
	return vm.NewEVM(context, state, b.hpb.chainConfig, vmCfg), vmError, nil
}

func (b *HpbApiBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.hpb.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *HpbApiBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.hpb.BlockChain().SubscribeChainEvent(ch)
}

func (b *HpbApiBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.hpb.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *HpbApiBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.hpb.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *HpbApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.hpb.BlockChain().SubscribeLogsEvent(ch)
}

func (b *HpbApiBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.hpb.txPool.AddLocal(signedTx)
}

func (b *HpbApiBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.hpb.txPool.Pending()
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
	return b.hpb.txPool.Get(hash)
}

func (b *HpbApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.hpb.txPool.State().GetNonce(addr), nil
}

func (b *HpbApiBackend) Stats() (pending int, queued int) {
	return b.hpb.txPool.Stats()
}

func (b *HpbApiBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.hpb.TxPool().Content()
}

func (b *HpbApiBackend) SubscribeTxPreEvent(ch chan<- core.TxPreEvent) event.Subscription {
	return b.hpb.TxPool().SubscribeTxPreEvent(ch)
}

func (b *HpbApiBackend) Downloader() *downloader.Downloader {
	return b.hpb.Downloader()
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

func (b *HpbApiBackend) EventMux() *event.TypeMux {
	return b.hpb.EventMux()
}

func (b *HpbApiBackend) AccountManager() *accounts.Manager {
	return b.hpb.AccountManager()
}

func (b *HpbApiBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.hpb.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *HpbApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.hpb.bloomRequests)
	}
}
