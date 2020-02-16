package lockAccount

import (
	"github.com/hpb-project/go-hpb/common"
	"math/big"
	"time"
)
// AllProjects  storage in stateDB, key: 'AllProjects', val: []projectState.Hash
// 1. add: when user create new project.
// 2. del: when project process finished.


// ProjectState storage in stateDB. key: 'ps' + hash, val: projectState
// 1. add: when user create new project.
// 2. del: when project process finished.
type ProjectState struct {
	Hash 		common.Hash		`json:"hash"`			// project hash
	Account 	common.Address	`json:"account"`		// account that created the project, no need calc send again.
	Tx			common.Hash		`json:"tx"`				// txHash that create the project, contain ProjectInfo
	JoinedNum   uint64			`json:"joinNum"`		// the number that has joined the project
	JoinedUsers []common.Address `json:"joinUsers"`		// the user that join the project
}

// AllUsers storage in stateDB, key: 'AllUsers', val: []userAddr
// 1. add: when user first time lock account.
// 2. del: when user's lockRecord all finished.

// UserLockState storage in stateDB, key: 'ul' + addr, val: userLockState
type UserLockState struct {
	TotalNumber uint64			`json:"totalNumber"`	// number that total locked.
	WaitUnlock	bool			`json:"waitUnlock"`		// flag waitUnlock
	NumberToUnlock uint64		`json:"numberToUnlock"` // number to unlock
	BlockToUnlock  *big.Int		`json:"blockToUnlock"`  // the unlock process block number.
}

// ProjectInfo response for query.
type ProjectInfo struct {
	Hash 		common.Hash		`json:"hash"`
	Account 	common.Address	`json:"account"`
	JoinedNum   uint64			`json:"joinNum"`
	LockPeriods uint32 			`json:"periods"`
	CycleTime   uint32 			`json:"cycleTime"`
	BenefitRate uint32 			`json:"rate"`
	MinValue	uint64			`json:"minValue"`
	MaxValue 	uint64			`json:"maxValue"`
	TotalNumber uint64			`json:"totalNum"`
	JoinDeadLine uint64			`json:"deadLine"`
}

// UserState storage in stateDB. key: 'us' + addr, val: userState
type UserState struct {

}



type LockProject struct {
	Hash		common.Hash		`json:"hash"`			// project hash
	Account     common.Address 	`json:"account"`		// account that created the project
	LockPeriods uint32 			`json:"lockPeriods"`	// total periods to unlock
	CycleTime   uint32 			`json:"cycleTime"`		// cycle per period, unit(hour)
	BenefitRate uint32 			`json:"benefitRate"`	// benefit for address
	MinValue    uint64 			`json:"minValue"`		// min HPB token number per address to lock
	MaxValue    uint64 			`json:"maxValue"`		// max HPB token number per address to lock
	TotalNumber uint64 			`json:"totalNumber"`	// max HPB token number for all address
	Deadline    time.Time 		`json:"deadLine"`		// deadline to join the project.
}

type LockRecord struct {
	Account		common.Address	`json:"account"`		// record's owner
	Project 	common.Hash 	`json:"project"`		// project hash, empty is not join any project
	LockPeriods uint32			`json:"lockPeriods"`	// total periods to lock.
	CycleTime   uint32			`json:"cycleTime"`		// cycle time per period, unit (hour)
	LeftPeriods uint32			`json:"leftPeriods"`	// left periods to unlock
	Number      uint64			`json:"number"`			// total HPB token number start lock
	LeftNumber  uint64 			`json:"leftNumber"`		// left HPB token number locked.
}

type UnlockRecord struct {

}

type ModuleLockInfo struct {
	Projects []LockProject
	Records []LockRecord
}

type CommonParam struct {
	MaxLockedRecordCountPerAddr uint32
}
