package types

import (
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

type ModuleInterface interface {
	ModuleInit() error
	ModuleClose() error
	ModuleBlockStart(block *types.Block, statedb *state.StateDB) error
	ModuleBlockEnd(block *types.Block, statedb *state.StateDB) error
	CreateTransaction() (types.Transaction, error)
	ValidateTransaction() error
	ProcessTransaction(tx *types.Transaction, statedb *state.StateDB) error
	ProcessQuery() error
}

