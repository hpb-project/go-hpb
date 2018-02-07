// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package les

import (
	"context"
	"math/big"

	"github.com/hpb-project/go-hpb/accounts"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/math"
	"github.com/hpb-project/go-hpb/core"
	"github.com/hpb-project/go-hpb/core/bloombits"
	"github.com/hpb-project/go-hpb/core/state"
	"github.com/hpb-project/go-hpb/core/types"
	"github.com/hpb-project/go-hpb/core/vm"
	"github.com/hpb-project/go-hpb/hpb/downloader"
	"github.com/hpb-project/go-hpb/hpb/gasprice"
	"github.com/hpb-project/go-hpb/hpbdb"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/light"
	"github.com/hpb-project/go-hpb/params"
	"github.com/hpb-project/go-hpb/rpc"
)

type LesApiBackend struct {
	hpb *LightHpbereum
	gpo *gasprice.Oracle
}

func (b *LesApiBackend) ChainConfig() *params.ChainConfig {
	return b.hpb.chainConfig
}

func (b *LesApiBackend) CurrentBlock() *types.Block {
	return types.NewBlockWithHeader(b.hpb.BlockChain().CurrentHeader())
}

func (b *LesApiBackend) SetHead(number uint64) {
	b.hpb.protocolManager.downloader.Cancel()
	b.hpb.blockchain.SetHead(number)
}

func (b *LesApiBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	if blockNr == rpc.LatestBlockNumber || blockNr == rpc.PendingBlockNumber {
		return b.hpb.blockchain.CurrentHeader(), nil
	}

	return b.hpb.blockchain.GetHeaderByNumberOdr(ctx, uint64(blockNr))
}

func (b *LesApiBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, err
	}
	return b.GetBlock(ctx, header.Hash())
}

func (b *LesApiBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	return light.NewState(ctx, header, b.hpb.odr), header, nil
}

func (b *LesApiBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	return b.hpb.blockchain.GetBlockByHash(ctx, blockHash)
}

func (b *LesApiBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	return light.GetBlockReceipts(ctx, b.hpb.odr, blockHash, core.GetBlockNumber(b.hpb.chainDb, blockHash))
}

func (b *LesApiBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.hpb.blockchain.GetTdByHash(blockHash)
}

func (b *LesApiBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	context := core.NewEVMContext(msg, header, b.hpb.blockchain, nil)
	return vm.NewEVM(context, state, b.hpb.chainConfig, vmCfg), state.Error, nil
}

func (b *LesApiBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.hpb.txPool.Add(ctx, signedTx)
}

func (b *LesApiBackend) RemoveTx(txHash common.Hash) {
	b.hpb.txPool.RemoveTx(txHash)
}

func (b *LesApiBackend) GetPoolTransactions() (types.Transactions, error) {
	return b.hpb.txPool.GetTransactions()
}

func (b *LesApiBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	return b.hpb.txPool.GetTransaction(txHash)
}

func (b *LesApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.hpb.txPool.GetNonce(ctx, addr)
}

func (b *LesApiBackend) Stats() (pending int, queued int) {
	return b.hpb.txPool.Stats(), 0
}

func (b *LesApiBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.hpb.txPool.Content()
}

func (b *LesApiBackend) SubscribeTxPreEvent(ch chan<- core.TxPreEvent) event.Subscription {
	return b.hpb.txPool.SubscribeTxPreEvent(ch)
}

func (b *LesApiBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeChainEvent(ch)
}

func (b *LesApiBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeChainHeadEvent(ch)
}

func (b *LesApiBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeChainSideEvent(ch)
}

func (b *LesApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.hpb.blockchain.SubscribeLogsEvent(ch)
}

func (b *LesApiBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeRemovedLogsEvent(ch)
}

func (b *LesApiBackend) Downloader() *downloader.Downloader {
	return b.hpb.Downloader()
}

func (b *LesApiBackend) ProtocolVersion() int {
	return b.hpb.LesVersion() + 10000
}

func (b *LesApiBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *LesApiBackend) ChainDb() hpbdb.Database {
	return b.hpb.chainDb
}

func (b *LesApiBackend) EventMux() *event.TypeMux {
	return b.hpb.eventMux
}

func (b *LesApiBackend) AccountManager() *accounts.Manager {
	return b.hpb.accountManager
}

func (b *LesApiBackend) BloomStatus() (uint64, uint64) {
	return params.BloomBitsBlocks, 0
}

func (b *LesApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
}
