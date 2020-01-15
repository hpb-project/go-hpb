package lockAccount

import (
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/log"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"sync"
)

type LockAccountModule struct {
	mux sync.RWMutex
}

func NewLockAccountModule() *LockAccountModule {
	return &LockAccountModule{}
}

func (this LockAccountModule) ModuleInit() error {
	return nil
}

func (this LockAccountModule) ModuleClose() error {
	return nil
}

func (this LockAccountModule)ModuleBlockStart(block *types.Block, statedb *state.StateDB) error {
	header := block.Header()
	log.Info("Example BlockStart ", "block ", header.Number.Uint64())
	return nil
}

func (this LockAccountModule) ModuleBlockEnd(block *types.Block, statedb *state.StateDB) error {
	header := block.Header()
	log.Info("Example BlockEnd ", "block ", header.Number.Uint64())
	return nil
}

func (this LockAccountModule)GetTxHandler(tx *types.Transaction) bc.TxHandler {
	data := tx.Data()
	ex := &mtypes.LockAccountModuleMsg{}
	if err := proto.Unmarshal(data, ex); err != nil {
		return nil
	}
	switch ex.Value.(type) {
	case *mtypes.LockAccountModuleMsg_Record:
		return handleNewLockToken
	case *mtypes.LockAccountModuleMsg_Project:
		return handleNewProject
	default:
		return nil
	}
}

func (this LockAccountModule)GetTxValidator(tx *types.Transaction) bc.TxValidator {
	data := tx.Data()
	ex := &mtypes.Example{}
	if err := proto.Unmarshal(data, ex); err != nil {
		return nil
	}
	switch ex.Value.(type) {
	case *mtypes.Example_Add:
		return validateAdd
	case *mtypes.Example_Mul:
		return validateMul
	default:
		return nil
	}
}

func (this LockAccountModule)GetQuerier(cmd string) bc.Querier{
	switch cmd{
	case QueryMethods:
		return handleQueryMethods
	case QueryMethodAdd:
		return handleQueryAdd
	case QueryMethodMul:
		return handleQueryMul
	default:
		return nil
	}
}

















