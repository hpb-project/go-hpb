package lockAccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"gopkg.in/fatih/set.v0"
)

const (
	//query cmds
	QueryMethods		= "methods"		// methods
	QueryAllUsers		= "allUsers"	// all users
	QueryAllFrozen		= "allFrozen"	// all frozen
	QueryUserInfo		= "userInfo"	// user info
	QueryLockStatus		= "status"		// stat
	QueryLockDetail		= "detail"		// detail
)

type MethodsResponse struct {
	Methods 	[]string	`json:"methods"`
}
func (this *LockAccountModule)handleQueryMethods(header *types.Header, db *state.StateDB, data []byte) (string, error) {
	var res = MethodsResponse{Methods:make([]string,0)}
	res.Methods = append(res.Methods, QueryMethods, QueryAllUsers, QueryAllFrozen, QueryUserInfo, QueryLockStatus, QueryLockDetail)
	ret, err := json.Marshal(res)
	return string(ret), err
}

type AllUsersResponse struct {
	Users []common.Address	`json:"users"`
}
func (this *LockAccountModule)handleQueryAllUsers(header *types.Header, db *state.StateDB, data []byte)( string, error) {
	var res = AllUsersResponse{Users:make([]common.Address, 0)}
	allUsers, err := this.AllUsersGet(db)
	if err != nil {
		return "", err
	}
	copy(res.Users, allUsers)
	ret, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

type UserFrozenStat struct {
	Number  	uint64				`json:"number"`
	StartTime 	uint64				`json:"startTime"`
	EndTime		uint64				`json:"endTime"`
}
type AllFrozenResponse struct {
	UserStates 	map[common.Address]UserFrozenStat		`json:"states"`
	TotalFrozen uint64									`json:"total"`
}
func (this *LockAccountModule)handleQueryAllFrozen(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	var res = AllFrozenResponse{UserStates:make(map[common.Address]UserFrozenStat)}
	allFrozen, err := this.AllFrozenStatesGet(db)
	if err != nil {
		return "", err
	}
	for _, frozen := range allFrozen {
		userstate, err := this.UserStateGet(db, frozen.Addr)
		if err != nil {
			continue
		}
		ufs := UserFrozenStat{userstate.FrozenNumber,frozen.StartTime, frozen.StartTime + frozen.WaitTime}
		res.UserStates[frozen.Addr] = ufs
	}
	ret, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

type UserInfoRequest struct {
	Addr 		common.Address 		`json:"addr"`
}
type UserInfoResponse struct {
	Addr 		common.Address		`json:"addr"`
	LockNumber	uint64				`json:"locked"`
	HasFrozen	bool				`json:"hasFrozen"`
	FrozenState *UserFrozenStat		`json:"frozen,omitempty"`
}
func (this *LockAccountModule)handleQueryUserInfo(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	var req UserInfoRequest
	err := json.Unmarshal(data, &req)
	if err != nil {
		return "", errors.New("unmarshal data failed")
	}

	var res = UserInfoResponse{Addr:req.Addr}
	userState, err := this.UserStateGet(db, req.Addr)
	if err != nil {
		return "", err
	}
	res.Addr = req.Addr
	res.LockNumber = userState.LockedNumber
	res.HasFrozen = userState.HasFrozen

	if userState.HasFrozen {
		res.FrozenState = &UserFrozenStat{Number:userState.FrozenNumber}
		allFrozen, err := this.AllFrozenStatesGet(db)
		if err != nil {
			return "", err
		}
		for _, f := range allFrozen {
			if bytes.Compare(f.Addr.Bytes(), req.Addr.Bytes()) == 0 {
				res.FrozenState.StartTime = f.StartTime
				res.FrozenState.EndTime = f.StartTime + f.WaitTime
			}
		}
	}
	ret, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

type LockStatusResponse struct {
	TotalLocked		uint64		`json:"totalLocked"`
	TotalFrozen		uint64		`json:"totalFrozen"`
}
func (this *LockAccountModule)handleQueryLockStatus(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	var res LockStatusResponse
	allUsers, err := this.AllUsersGet(db)
	if err != nil {
		return "", err
	}
	for _, user := range allUsers {
		s, err := this.UserStateGet(db, user)
		if err != nil {
			return "", err
		}
		res.TotalLocked += s.LockedNumber
		res.TotalFrozen += s.FrozenNumber
	}
	ret, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

type LockDetailResponse struct {
	Status 	LockStatusResponse						`json:"status"`
	Detail  map[common.Address]UserInfoResponse		`json:"details"`
}
func (this *LockAccountModule)handleQueryLockDetail(header *types.Header, db *state.StateDB, data []byte)(string ,error) {
	var res = LockDetailResponse{Detail:make(map[common.Address]UserInfoResponse)}

	allUser, err := this.AllUsersGet(db)
	if err != nil {
		return "", err
	}
	allFrozen, err := this.AllFrozenStatesGet(db)
	if err != nil {
		return "", err
	}

	userSet := set.New(allUser)

	for _, f := range allFrozen {
		// the user have frozen.
		info := UserInfoResponse{Addr:f.Addr, HasFrozen:true,FrozenState:&UserFrozenStat{}}
		info.FrozenState.StartTime = f.StartTime
		info.FrozenState.EndTime = f.StartTime + f.WaitTime
		state, err := this.UserStateGet(db, f.Addr)
		if err != nil {
			return "", err
		}
		info.FrozenState.Number = state.FrozenNumber
		info.LockNumber = state.LockedNumber

		res.Detail[info.Addr] = info
		res.Status.TotalFrozen += state.FrozenNumber
		res.Status.TotalLocked += state.LockedNumber

		userSet.Remove(info.Addr)
	}
	for _, user := range allUser {
		// the user have no frozen.
		if userSet.Has(user) {
			info := UserInfoResponse{Addr:user, HasFrozen:false}
			state, err := this.UserStateGet(db, user)
			if err != nil {
				return "", err
			}
			info.LockNumber = state.LockedNumber

			res.Detail[user] = info
			res.Status.TotalLocked += state.LockedNumber
		}
	}
	ret, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}
