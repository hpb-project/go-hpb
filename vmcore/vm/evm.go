package vm

import (
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/hvm"
	hevm "github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/vmcore"
	"math/big"
)

func NewEVM(config *config.ChainConfig, msg vmcore.Message, header *types.Header, chain vmcore.ChainContext,
	author *common.Address, statedb vmcore.StateDB) vmcore.EVM {
	if header.Number.Uint64() < consensus.StageNumberEvmV2 {
		cfg := hevm.Config{}
		// Create a new context to be used in the EVM environment
		context := hvm.NewEVMContext(msg, header, chain, author)
		// Create a new environment which holds all relevant information
		// about the transaction and calling mechanisms.
		vmenv := hevm.NewEVM(context, statedb, config, cfg)
		return vmenv
	} else {
		// todo: add evm
	}
	return nil
}

func NewEVMForGeneration(config *config.ChainConfig, header *types.Header,
	author common.Address, statedb vmcore.StateDB, getHash func(uint64) common.Hash, gasPrice int64) vmcore.EVM {
	if header.Number.Uint64() < consensus.StageNumberEvmV2 {
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
	}
	return nil
}
