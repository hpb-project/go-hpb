package lockAccount

import (
	"encoding/hex"
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/consensus"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"sync"
)

const (
	LockAccountTableAddr = "0x0000000000000000000000000000000000000011"

	// AllProjects:		key: 'AllProejcts'			val: []project

	// ProjectUsers: 	key: 'pus' + projectHash 	val: []LockInfo
	// LockedUser:  	key: 'LockedUsers'			val: []addr
	// LockedUserInfo: 	key: 'usi' + addr			val: []LockInfo
	AllProjectsKey = "ExistProjects"	// val : []projectHash
	//ZoneRecordsKey = "ZoneRecords"
	ProjectInfoKeyPrefix = "PInfo"			// key : PI + projecthash
	UserLockInfoKeyPrefix = "lu"		// key : lu + addr value : all lockinfo.

	LockRecordsKey = "LockRecords"
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
	number := block.NumberU64()
	if number < consensus.LockAccountEnable {
		return nil
	}
	if number == consensus.LockAccountEnable {
		this.SetConfig(&DefaultParam, statedb)
	}
	// process all frozen states
	log.Info("Example BlockStart ", "block ", number)
	return nil
}

func (this LockAccountModule) ModuleBlockEnd(block *types.Block, statedb *state.StateDB) error {
	number := block.NumberU64()
	if number < consensus.LockAccountEnable {
		return nil
	}
	err := this.ProcessFrozenStates(block, statedb)
	if err != nil {
		return err
	}
	// process all frozen states
	log.Info("Example BlockStart ", "block ", number)
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
	case *mtypes.LockAccountModuleMsg_Lock:
		return this.handleLockMsg
	case *mtypes.LockAccountModuleMsg_Unlock:
		return this.handleUnLockMsg
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
	case *mtypes.LockAccountModuleMsg_Lock:
		return this.validateLockMsg
	case *mtypes.LockAccountModuleMsg_Unlock:
		return this.validateUnlockMsg
	default:
		return nil
	}
}

func (this LockAccountModule)GetQuerier(cmd string) bc.Querier{
	switch cmd{
	case QueryMethods:
		return this.handleQueryMethods
	case QueryAllUsers:
		return this.handleQueryAllUsers
	case QueryAllFrozen:
		return this.handleQueryAllFrozen
	case QueryUserInfo:
		return this.handleQueryUserInfo
	case QueryLockStatus:
		return this.handleQueryLockStatus
	case QueryLockDetail:
		return this.handleQueryLockDetail
	default:
		return nil
	}
}





