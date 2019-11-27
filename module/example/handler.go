package example

import (
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/common/log"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

func handleMul(header *types.Header, tx *types.Transaction, db *state.StateDB ) (err error) {
	data := tx.Data()
	mul := &mtypes.ParamMul{}
	err = proto.Unmarshal(data, mul)
	if err != nil {
		return err
	}
	log.Info("Execute module example", "tx type ", "Mul", "result", mul.A * mul.B)

	return nil
}


func handleAdd(header *types.Header, tx *types.Transaction, db *state.StateDB) (err error) {
	data := tx.Data()
	add := &mtypes.ParamAdd{}
	err = proto.Unmarshal(data, add)
	if err != nil {
		return err
	}
	log.Info("Execute module example", "tx type ", "Add", "result", add.A + add.B)

	return nil
}