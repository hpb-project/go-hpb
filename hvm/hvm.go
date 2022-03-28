package hvm

import (
	"math/big"

	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/hvm/evm"
	. "github.com/hpb-project/go-hpb/vmcore"
)

// NewEVMContextWithoutMessage creates a new context without message for use in the EVM.
func NewEVMContextWithoutMessage(header *types.Header, chain ChainContext, author *common.Address) evm.Context {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	var beneficiary common.Address
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation
	} else {
		beneficiary = *author
	}
	extra, _ := types.BytesToExtraDetail(header.Extra)
	return evm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     GetHashFn(header, chain),
		Miner:       beneficiary,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		Random:      extra.GetSignedLastRND()[:32],
	}
}
func NewEVMContextWithMessage(context evm.Context, msg Message) evm.Context {
	context.Origin = msg.From()
	context.GasPrice = new(big.Int).Set(msg.GasPrice())
	return context
}

// NewEVMContext creates a new context for use in the EVM.
func NewEVMContext(msg Message, header *types.Header, chain ChainContext, author *common.Address) evm.Context {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	var beneficiary common.Address
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation
	} else {
		beneficiary = *author
	}

	extra, _ := types.BytesToExtraDetail(header.Extra)
	return evm.Context{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     GetHashFn(header, chain),
		Origin:      msg.From(),
		Miner:       beneficiary,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        new(big.Int).Set(header.Time),
		Difficulty:  new(big.Int).Set(header.Difficulty),
		GasLimit:    new(big.Int).Set(header.GasLimit),
		GasPrice:    new(big.Int).Set(msg.GasPrice()),
		Random:      extra.GetSignedLastRND()[:32],
	}
}
