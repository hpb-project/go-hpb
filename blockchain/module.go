package bc

import (
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

type ModuleInterface interface {
	ModuleInit() error
	ModuleClose() error
	ModuleBlockStart(header *types.Header, statedb *state.StateDB) error
	ModuleBlockEnd(block *types.Header, statedb *state.StateDB) error
	//CreateTransaction(tx *types.Transaction, param []byte) error
	//ValidateTransaction(tx *types.Transaction, db *state.StateDB) error
	//ProcessTransaction(tx *types.Transaction, statedb *state.StateDB) error
	//ProcessQuery() error
	GetTxHandler(tx *types.Transaction) TxHandler
	GetTxValidator(tx *types.Transaction) TxValidator
	GetQuerier(cmd string) Querier
}

type TxHandler   = func (header *types.Header, tx *types.Transaction, db *state.StateDB) (err error)
type TxValidator = func (tx *types.Transaction, db *state.StateDB) (err error)
type Querier     = func (header *types.Header, db *state.StateDB, data []byte) (res string, err error)


var	modules = map[string]ModuleInterface{}

func RegisterModules(name string, m ModuleInterface) {
	if _, exist := modules[name]; exist {
		return
	}
	modules[name] = m
}

func GetModules() []ModuleInterface {
	mlist := make([]ModuleInterface, 0)
	for _, m := range modules {
		mlist = append(mlist, m)
	}
	return mlist
}

func GetModule(name string) ModuleInterface {
	if m, exist := modules[name]; exist {
		return m
	}
	return nil
}

