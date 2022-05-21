package vm

import (
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	hpbconfig "github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/evm"
	eevm "github.com/hpb-project/go-hpb/evm/vm"
	"github.com/hpb-project/go-hpb/hvm"
	hevm "github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/vmcore"
	"math/big"
)

func NewEVM(config *hpbconfig.ChainConfig, msg vmcore.Message, header *types.Header, chain vmcore.ChainContext,
	author *common.Address, statedb vmcore.StateDB) vmcore.EVM {
	blocknumber := header.Number.Uint64()
	if !hpbconfig.UseNewEvm(blocknumber) { // old evm
		cfg := hevm.Config{}
		// Create a new context to be used in the EVM environment
		context := hvm.NewEVMContext(msg, header, chain, author)
		// Create a new environment which holds all relevant information
		// about the transaction and calling mechanisms.
		vmenv := hevm.NewEVM(context, statedb, config, cfg)
		return vmenv
	} else { // new evm.
		cfg := eevm.Config{}
		txContext := evm.NewEVMTxContext(msg)
		blockContext := evm.NewEVMBlockContext(header, chain, author)
		return eevm.NewEVM(blockContext, txContext, statedb, config, cfg)
	}
}

func NewEVMForGeneration(config *hpbconfig.ChainConfig, header *types.Header,
	author common.Address, statedb vmcore.StateDB, getHash func(uint64) common.Hash, gasPrice int64) vmcore.EVM {
	blocknumber := header.Number.Uint64()
	if !hpbconfig.UseNewEvm(blocknumber) {
		context := hevm.Context{
			CanTransfer: vmcore.CanTransfer,
			Transfer:    vmcore.Transfer,
			GetHash:     getHash,
			Origin:      author,
			Miner:       author,
			BlockNumber: new(big.Int).Set(header.Number),
			Time:        new(big.Int).Set(header.Time),
			Difficulty:  new(big.Int).Set(header.Difficulty),
			GasLimit:    new(big.Int).Set(header.GasLimit),
			GasPrice:    new(big.Int).Set(big.NewInt(gasPrice)),
		}
		cfg := hevm.Config{}
		vmenv := hevm.NewEVM(context, statedb, config, cfg)
		return vmenv
	} else {
		// todo: add evm
		cfg := eevm.Config{}
		txContext := eevm.TxContext{
			Origin:   author,
			GasPrice: new(big.Int).Set(big.NewInt(gasPrice)),
		}
		extra, _ := types.BytesToExtraDetail(header.Extra)
		blockContext := eevm.BlockContext{
			CanTransfer: vmcore.CanTransfer,
			Transfer:    vmcore.Transfer,
			GetHash:     getHash,
			Coinbase:    author,
			BlockNumber: new(big.Int).Set(header.Number),
			Time:        new(big.Int).Set(header.Time),
			Difficulty:  new(big.Int).Set(header.Difficulty),
			GasLimit:    header.GasLimit.Uint64(),
			Random:      extra.GetSignedLastRND()[:32],
		}
		return eevm.NewEVM(blockContext, txContext, statedb, config, cfg)
	}
}
