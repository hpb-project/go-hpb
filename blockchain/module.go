package bc

import (
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

type ModuleInterface interface {
	ModuleInit() error
	ModuleClose() error
	ModuleBlockStart(block *types.Block, statedb *state.StateDB) error
	ModuleBlockEnd(block *types.Block, statedb *state.StateDB) error
	CreateTransaction(tx *types.Transaction, param []byte) error
	ValidateTransaction(tx *types.Transaction, db *state.StateDB) error
	ProcessTransaction(tx *types.Transaction, statedb *state.StateDB) error
	ProcessQuery() error
}