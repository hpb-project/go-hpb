package example

import (
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/log"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"errors"
	"sync"
)

type ExampleModule struct {
	db *state.StateDB
	mux sync.RWMutex
}

func NewExampleModule(db *state.StateDB) *ExampleModule {
	return &ExampleModule{db:db}
}

func (*ExampleModule) ModuleInit() error {
	return nil
}

func (*ExampleModule) ModuleClose() error {
	return nil
}

func (*ExampleModule)ModuleBlockStart(block *types.Block, statedb *state.StateDB) error {
	header := block.Header()
	log.Info("Example BlockStart ", "block ", header.Number.Uint64())
	return nil
}

func (*ExampleModule) ModuleBlockEnd(block *types.Block, statedb *state.StateDB) error {
	header := block.Header()
	log.Info("Example BlockEnd ", "block ", header.Number.Uint64())
	return nil
}

func (*ExampleModule) ValidateTransaction(tx *types.Transaction, db *state.StateDB) error {
	example := &mtypes.Example{}
	param := tx.Data()
	if err := proto.Unmarshal(param, example); err != nil {
		return err
	}

	return nil
}

func (*ExampleModule) ProcessTransaction(tx *types.Transaction, db *state.StateDB) error {
	example := &mtypes.Example{}
	param := tx.Data()
	if err := proto.Unmarshal(param, example); err != nil {
		return err
	}
	return processExample(example)
}
func (*ExampleModule) ProcessQuery() error {
	return nil
}

func processExample(ex *mtypes.Example) error {
	switch ex.Value.(type) {
	case *mtypes.Example_Mul:
		msm, ok :=ex.Value.(*mtypes.Example_Mul)
		if ok {
			fmt.Printf("ExampleMul a * b = %d\n", msm.Mul.A * msm.Mul.B)
		}
	case *mtypes.Example_Add:
		msm, ok :=ex.Value.(*mtypes.Example_Add)
		if ok {
			fmt.Printf("ExampleMul a + b = %d\n", msm.Add.A + msm.Add.B)
		}
	default:
		return errors.New("Unknown example type.")
	}
	return nil
}

