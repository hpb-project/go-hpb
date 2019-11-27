package example

import (
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/log"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"sync"
)

type ExampleModule struct {
	mux sync.RWMutex
}

func NewExampleModule() ExampleModule {
	return ExampleModule{}
}

func (this ExampleModule) ModuleInit() error {
	return nil
}

func (this ExampleModule) ModuleClose() error {
	return nil
}

func (this ExampleModule)ModuleBlockStart(block *types.Block, statedb *state.StateDB) error {
	header := block.Header()
	log.Info("Example BlockStart ", "block ", header.Number.Uint64())
	return nil
}

func (this ExampleModule) ModuleBlockEnd(block *types.Block, statedb *state.StateDB) error {
	header := block.Header()
	log.Info("Example BlockEnd ", "block ", header.Number.Uint64())
	return nil
}

func (this ExampleModule)GetTxHandler(tx *types.Transaction) bc.TxHandler {
	data := tx.Data()
	ex := &mtypes.Example{}
	if err := proto.Unmarshal(data, ex); err != nil {
		return nil
	}
	switch ex.Value.(type) {
	case *mtypes.Example_Add:
		return handleAdd
	case *mtypes.Example_Mul:
		return handleMul
	default:
		return nil
	}
}

func (this ExampleModule)GetTxValidator(tx *types.Transaction) bc.TxValidator {
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

func (this ExampleModule)GetQuerier(cmd string) bc.Querier{
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

