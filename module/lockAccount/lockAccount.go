package lockAccount

import (
	"encoding/hex"
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"sync"
)

const (
	LockAccountTableAddr = "0x0000000000000000000000000000000000000011"
)

type LockAccountModule struct {
	LockDataAddr common.Address
	mux sync.RWMutex
}

func NameToAddr(table string) (common.Address,error) {
	bytes,err := hex.DecodeString(table)
	if err != nil {
		return common.Address{}, err
	}
	addr := common.Address{}
	addr.SetBytes(bytes)
	return addr, nil
}

func NewLockAccountModule() *LockAccountModule {
	tableAddr, err := NameToAddr(LockAccountTableAddr)
	if  err != nil {
		return nil
	} else {
		return &LockAccountModule{LockDataAddr:tableAddr}
	}
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
		return this.handleNewLockToken
	case *mtypes.LockAccountModuleMsg_Project:
		return this.handleNewProject
	default:
		return nil
	}
}

func (this LockAccountModule)GetTxValidator(tx *types.Transaction) bc.TxValidator {
	data := tx.Data()
	ex := &mtypes.LockAccountModuleMsg{}
	if err := proto.Unmarshal(data, ex); err != nil {
		return nil
	}
	switch ex.Value.(type) {
	case *mtypes.LockAccountModuleMsg_Project:
		return this.validateProject
	case *mtypes.LockAccountModuleMsg_Record:
		return this.validateRecord
	default:
		return nil
	}
}

func (this LockAccountModule)GetQuerier(cmd string) bc.Querier{
	switch cmd{
	case QueryMethods:
		return this.handleQueryMethods
	case QueryMethodProjects:
		return this.handleQueryProjects
	case QueryMethodRecords:
		return this.handleQueryRecords
	default:
		return nil
	}
}

















