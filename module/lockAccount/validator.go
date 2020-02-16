package lockAccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/config"
	mtypes "github.com/hpb-project/go-hpb/module/types"
	"math/big"
	"time"
)

func weiToHpb(wei *big.Int) uint64 {
	unit := big.NewInt(10E18)
	hpb := big.NewInt(0)
	hpb.Div(wei,unit)
	return hpb.Uint64()
}

func (this *LockAccountModule)validateProject(tx *types.Transaction, db *state.StateDB ) error {
	amount := tx.Value().Uint64()
	if amount > 0 {
		return errors.New("Amount must be zero(0)")
	}
	data := tx.Data()
	project := &mtypes.NewLockProjectMsg{}
	if err := proto.Unmarshal(data, project); err != nil {
		return err
	}
	signer := types.NewBoeSigner(config.GetHpbConfigInstance().BlockChain.ChainId)
	from,_ := types.Sender(signer,tx)

	fromState := db.GetOrNewStateObject(from)
	rem := big.NewInt(0).Sub(fromState.Balance(), tx.Cost()) // wei
	bHpb := weiToHpb(rem)
	cost := uint64(project.BenefitRate) * project.TotalNumber / 100
	if bHpb < cost {
		//
		return errors.New("insufficient funds for benefitRate * TotalNumber + Gas")
	}
	if project.MinValue >= project.MaxValue {
		return errors.New("invalid param minValue >= maxValue")
	}
	if project.MinValue >= project.TotalNumber {
		return errors.New("invalid param minValue >= totalNumber")
	}
	if bytes.Compare(from.Bytes(),project.Account) != 0 {
		return errors.New("invalid param from, must be tx's owner ")
	}
	if project.LockPeriods == 0 {
		return errors.New("invalid param lockePeriods")
	}
	if project.CycleTime == 0 || project.CycleTime % 200 != 0 {
		return errors.New("invalid param cycleTime, should be N*200")
	}
	if project.Deadine < uint64(time.Now().Unix() + 60*60*24*3) {
		return errors.New("invalid param deadline, shoule at least 3 days later from now")
	}
	return nil

}


func (this *LockAccountModule)validateRecord(tx *types.Transaction, db *state.StateDB) error {
	amount := tx.Value().Uint64()
	if amount > 0 {
		return errors.New("Amount must be zero(0)")
	}
	data := tx.Data()
	record := &mtypes.NewLockTokenMsg{}
	if err := proto.Unmarshal(data, record); err != nil {
		return err
	}
	signer := types.NewBoeSigner(config.GetHpbConfigInstance().BlockChain.ChainId)
	from,_ := types.Sender(signer,tx)

	fromState := db.GetOrNewStateObject(from)
	rem := big.NewInt(0).Sub(fromState.Balance(), tx.Cost()) // wei
	bHpb := weiToHpb(rem)

	if bHpb < record.Number {
		// check balance
		return errors.New("insufficient funds for LockNumber + Gas")
	}

	if record.CycleTime == 0 || record.CycleTime%200 != 0 {
		return errors.New("invalid param cycleTime, should be N*200 block")
	}
	if record.LockPeriods == 0 {
		return errors.New("invalid param lockPeriods")
	}

	if len(record.Project) > 0 {
		var projects []LockProject
		// check with project info.
		encode := db.GetValue(this.LockDataAddr, common.StringToHash(ProjectsKeY))
		if len(encode) == 0 {
			return errors.New("invalid param, not found project")
		}
		if err := json.Unmarshal(encode, &projects); err != nil {
			return errors.New("unmarshal projects failed")
		}
		for _, p := range projects {
			if bytes.Compare(record.Project, p.Hash.Bytes()) == 0 {
				// find project.
				// check number
				if record.Number < p.MinValue || record.Number > p.MaxValue {
					return errors.New("invalid param Number")
				}
				break
			}
		}
		return errors.New("invalid param project, not found")
	}
	return nil
}
