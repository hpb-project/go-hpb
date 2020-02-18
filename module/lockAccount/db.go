package lockAccount

import (
	"encoding/json"
	"errors"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"gopkg.in/fatih/set.v0"
)

/*
 * Simple Lock Module.
 */
// CommonParam storage in stateDB, key: 'Config', val: commonParam
type CommonParam struct {
	MinUnlockFrozenTime uint64 // min unlock token frozen time (unit Day).
}
// AllUsers storage in stateDB, key: 'AllUsers', val: []addr
// 1. Add, new user create lock tx.
// 2. Del, user have no locked token.
type Allusers struct {
	Users 		[]common.Address	`json:"users"`
}

// UserState storage in stateDB. key: 'us' + addr, val: userState
// 1. Add, user create lock tx firsttime.
// 2. Update, user create lock tx.
// 3. Del, user have no locked token.
type UserState struct {
	LockedNumber uint64 		`json:"lockedNumber"`
	HasFrozen	 bool 			`json:"hasFrozen"`
	FrozenNumber uint64 		`json:"frozenNumber"`
}

// AllFrozen storage in stateDB, key: 'AllFrozens', val: []frozenState
type FrozenStates struct {
	Frozens 	[]FrozenState	`json:frozens`
}

type FrozenState struct {
	Addr 		common.Address	`json:"addr"`
	StartTime  	uint64 			`json:"startTime"`
	WaitTime	uint64 			`json:"waitTime"`
}
const (
	CONFIGKEY = "Config"
	AllUsersKey = "AllUsers"
	AllFrozensKey = "AllFrozens"
	UserStateKeyPrefix = "us"
)

var DefaultParam = CommonParam{
	MinUnlockFrozenTime:7,
}

func (this *LockAccountModule)GetConfig(db *state.StateDB) (*CommonParam, error) {
	var param CommonParam
	// check with project info.
	encode := db.GetValue(this.LockDataAddr, common.StringToHash(CONFIGKEY))
	if len(encode) == 0 {
		defaultParam,_ := json.Marshal(DefaultParam)
		db.SetValue(this.LockDataAddr, common.StringToHash(CONFIGKEY), defaultParam)
		param = DefaultParam
	} else {
		if err := json.Unmarshal(encode, &param); err != nil {
			return nil, err
		}
	}
	return &param, nil
}

func (this *LockAccountModule)AllUsersGet(db *state.StateDB) ([]common.Address, error){
	var users []common.Address
	// check with project info.
	encode := db.GetValue(this.LockDataAddr, common.StringToHash(AllUsersKey))
	if len(encode) > 0 {
		if err := json.Unmarshal(encode, &users); err != nil {
			return nil, err
		}
	}
	return users, nil
}

func (this *LockAccountModule)AllUsersSet(users []common.Address, db *state.StateDB) error {
	if decode,err := json.Marshal(users); err != nil {
		return err
	} else {
		db.SetValue(this.LockDataAddr, common.StringToHash(AllUsersKey), decode)
	}
	return nil
}

func (this *LockAccountModule)UserStateGet(db *state.StateDB, addr common.Address) (*UserState, error) {
	var us = UserState{LockedNumber:0, HasFrozen:false, FrozenNumber:0}
	var key = UserStateKeyPrefix + addr.String()
	encode := db.GetValue(addr, common.StringToHash(key))
	if len(encode) > 0 {
		if err := json.Unmarshal(encode, &us); err != nil {
			return nil, err
		}
	}
	return &us, nil
}

func (this *LockAccountModule)UserSateSet(db *state.StateDB, addr common.Address, state *UserState) error {
	if decode,err := json.Marshal(state); err != nil {
		return err
	} else {
		var key = UserStateKeyPrefix + addr.String()
		db.SetValue(this.LockDataAddr, common.StringToHash(key), decode)
	}
	return nil
}

func (this *LockAccountModule)UserStateDel(db *state.StateDB, addr common.Address) error {
	var val []byte
	var key = UserStateKeyPrefix + addr.String()
	db.SetValue(this.LockDataAddr, common.StringToHash(key), val) // set value length 0 will delete key.
	return nil
}

func (this *LockAccountModule)AllFrozenStatesGet(db *state.StateDB) ([]FrozenState, error) {
	var frozenStates []FrozenState
	encode := db.GetValue(this.LockDataAddr, common.StringToHash(AllFrozensKey))
	if len(encode) > 0 {
		if err := json.Unmarshal(encode, &frozenStates); err != nil {
			return nil, err
		}
	}
	return frozenStates, nil
}

func (this *LockAccountModule)AllFrozenStatesSet(db *state.StateDB, fs []FrozenState) error {
	if decode,err := json.Marshal(fs); err != nil {
		return err
	} else {
		db.SetValue(this.LockDataAddr, common.StringToHash(AllFrozensKey), decode)
	}
	return nil
}


func (this *LockAccountModule) ProcessLockMsg(from common.Address, lock *mtypes.LockMsg, db *state.StateDB) error {
	fromState := db.GetOrNewStateObject(from)
	balance := fromState.Balance()
	lockwei := hpbToWei(lock.Number)
	if balance.Cmp(lockwei) < 0 {
		return errors.New("balance not enough")
	}

	// get user state.
	if userState, err := this.UserStateGet(db, from); err != nil {
		return errors.New("get data failed")
	} else {
		userState.LockedNumber += lock.Number
		if err = this.UserSateSet(db, from, userState); err != nil {
			return errors.New("set data failed")
		}
	}

	// sub balance
	fromState.SubBalance(lockwei)

	// add user in AllUsers.
	if allUser, err := this.AllUsersGet(db); err != nil {
		return errors.New("get data failed")
	} else {
		var userSet = set.New()
		userSet.Add(allUser)
		if !userSet.Has(from) {
			allUser = append(allUser, from)
			if err = this.AllUsersSet(allUser, db); err != nil {
				return errors.New("set data failed")
			}
		}
	}
	return nil
}


func (this *LockAccountModule) ProcessUnLockMsg(header *types.Header, from common.Address, unlock *mtypes.UnlockMsg, db *state.StateDB) error {
	// check user in AllUsers.
	if allUser, err := this.AllUsersGet(db); err != nil {
		return errors.New("get data failed")
	} else {
		var userSet = set.New()
		userSet.Add(allUser)
		if !userSet.Has(from) {
			return errors.New("user have no locked token")
		}
	}

	frozenStates, err := this.AllFrozenStatesGet(db)
	if err != nil {
		return errors.New("get data failed")
	}

	// get user state.
	if userState, err := this.UserStateGet(db, from); err != nil {
		return errors.New("get data failed")
	} else {
		if userState.HasFrozen {
			return errors.New("can't unlock token when has frozen not finished")
		} else {
			userState.FrozenNumber = unlock.Number
			userState.HasFrozen = true
			if err = this.UserSateSet(db, from, userState); err != nil {
				return errors.New("set data failed")
			}

			userFrozen := FrozenState{Addr:from, StartTime:header.Time.Uint64(), WaitTime:unlock.FrozenTime}
			frozenStates = append(frozenStates, userFrozen)
			err = this.AllFrozenStatesSet(db, frozenStates)
			if err != nil {
				return errors.New("set data failed")
			}
		}
	}

	return nil
}