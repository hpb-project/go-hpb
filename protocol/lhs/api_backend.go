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

package lhs

import (
	"context"
	"math/big"

	"github.com/hpb-project/ghpb/account"
	"github.com/hpb-project/ghpb/common"
	"github.com/hpb-project/ghpb/common/constant"
	"github.com/hpb-project/ghpb/common/math"
	"github.com/hpb-project/ghpb/core"
	"github.com/hpb-project/ghpb/core/bloombits"
	"github.com/hpb-project/ghpb/core/event"
	"github.com/hpb-project/ghpb/core/state"
	"github.com/hpb-project/ghpb/core/types"
	"github.com/hpb-project/ghpb/core/vm"
	"github.com/hpb-project/ghpb/network/rpc"
	"github.com/hpb-project/ghpb/protocol/downloader"
	"github.com/hpb-project/ghpb/protocol/gasprice"
	"github.com/hpb-project/ghpb/protocol/light"
	"github.com/hpb-project/ghpb/storage"
)

type LhsApiBackend struct {
	hpb *LightHpb
	gpo *gasprice.Oracle
}

func (b *LhsApiBackend) ChainConfig() *params.ChainConfig {
	return b.hpb.chainConfig
}

func (b *LhsApiBackend) CurrentBlock() *types.Block {
	return types.NewBlockWithHeader(b.hpb.BlockChain().CurrentHeader())
}

func (b *LhsApiBackend) SetHead(number uint64) {
	b.hpb.protocolManager.downloader.Cancel()
	b.hpb.blockchain.SetHead(number)
}

func (b *LhsApiBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	if blockNr == rpc.LatestBlockNumber || blockNr == rpc.PendingBlockNumber {
		return b.hpb.blockchain.CurrentHeader(), nil
	}

	return b.hpb.blockchain.GetHeaderByNumberOdr(ctx, uint64(blockNr))
}

func (b *LhsApiBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, err
	}
	return b.GetBlock(ctx, header.Hash())
}

func (b *LhsApiBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	header, err := b.HeaderByNumber(ctx, blockNr)
	if header == nil || err != nil {
		return nil, nil, err
	}
	return light.NewState(ctx, header, b.hpb.odr), header, nil
}

func (b *LhsApiBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	return b.hpb.blockchain.GetBlockByHash(ctx, blockHash)
}

func (b *LhsApiBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	return light.GetBlockReceipts(ctx, b.hpb.odr, blockHash, core.GetBlockNumber(b.hpb.chainDb, blockHash))
}

func (b *LhsApiBackend) GetTd(blockHash common.Hash) *big.Int {
	return b.hpb.blockchain.GetTdByHash(blockHash)
}

func (b *LhsApiBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	state.SetBalance(msg.From(), math.MaxBig256)
	context := core.NewEVMContext(msg, header, b.hpb.blockchain, nil)
	return vm.NewEVM(context, state, b.hpb.chainConfig, vmCfg), state.Error, nil
}

func (b *LhsApiBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.hpb.txPool.Add(ctx, signedTx)
}

func (b *LhsApiBackend) RemoveTx(txHash common.Hash) {
	b.hpb.txPool.RemoveTx(txHash)
}

func (b *LhsApiBackend) GetPoolTransactions() (types.Transactions, error) {
	return b.hpb.txPool.GetTransactions()
}

func (b *LhsApiBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	return b.hpb.txPool.GetTransaction(txHash)
}

func (b *LhsApiBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.hpb.txPool.GetNonce(ctx, addr)
}

func (b *LhsApiBackend) Stats() (pending int, queued int) {
	return b.hpb.txPool.Stats(), 0
}

func (b *LhsApiBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.hpb.txPool.Content()
}

func (b *LhsApiBackend) SubscribeTxPreEvent(ch chan<- core.TxPreEvent) event.Subscription {
	return b.hpb.txPool.SubscribeTxPreEvent(ch)
}

func (b *LhsApiBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeChainEvent(ch)
}

func (b *LhsApiBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeChainHeadEvent(ch)
}

func (b *LhsApiBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeChainSideEvent(ch)
}

func (b *LhsApiBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.hpb.blockchain.SubscribeLogsEvent(ch)
}

func (b *LhsApiBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.hpb.blockchain.SubscribeRemovedLogsEvent(ch)
}

func (b *LhsApiBackend) Downloader() *downloader.Downloader {
	return b.hpb.Downloader()
}

func (b *LhsApiBackend) ProtocolVersion() int {
	return b.hpb.LesVersion() + 10000
}

func (b *LhsApiBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *LhsApiBackend) ChainDb() hpbdb.Database {
	return b.hpb.chainDb
}

func (b *LhsApiBackend) EventMux() *event.TypeMux {
	return b.hpb.eventMux
}

func (b *LhsApiBackend) AccountManager() *accounts.Manager {
	return b.hpb.accountManager
}

func (b *LhsApiBackend) BloomStatus() (uint64, uint64) {
	return params.BloomBitsBlocks, 0
}

func (b *LhsApiBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
}
