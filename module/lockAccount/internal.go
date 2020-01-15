package lockAccount

import (
	"github.com/hpb-project/go-hpb/common"
	"time"
)

type LockProject struct {
	Account     common.Address // account that created the project
	LockPeriods uint32 // total periods to unlock
	CycleTime   uint32 // cycle per period, unit(hour)
	BenefitRate uint32 // benefit for address
	MinValue    uint64 // min HPB token number per address to lock
	MaxValue    uint64 // max HPB token number per address to lock
	TotalNumber uint64 // max HPB token number for all address
	Deadline    time.Time // deadline to join the project.
}

type LockRecord struct {
	Project 	common.Hash // project hash, empty is not join any project
	LockPeriods uint32		// total periods to lock.
	CycleTime   uint32		// cycle time per period, unit (hour)
	LeftPeriods uint32		// left periods to unlock
	Number      uint64		// total HPB token number start lock
	LeftNumber  uint64 		// left HPB token number locked.
}

type ModuleLockInfo struct {
	Projects []LockProject
	Records []LockRecord
}

type CommonParam struct {
	MaxLockedRecordCountPerAddr uint32
}
