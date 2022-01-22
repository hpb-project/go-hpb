package vm

import (
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/hvm"
	hevm "github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/vmcore"
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
		// todo: add vm
	}
	return nil
}
