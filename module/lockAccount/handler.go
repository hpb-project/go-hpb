package lockAccount

import (
	"errors"
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/config"
	mtypes "github.com/hpb-project/go-hpb/module/types"
)

func (this *LockAccountModule) handleNewProject(header *types.Header, tx *types.Transaction, db *state.StateDB ) (err error) {
	if err = this.validateProject(tx,db); err != nil {
		return err
	}
	data := tx.Data()
	project := &mtypes.NewLockProjectMsg{}
	err = proto.Unmarshal(data, project)
	if err != nil {
		return err
	}



	return nil
}


func (this *LockAccountModule)handleNewLockToken(header *types.Header, tx *types.Transaction, db *state.StateDB) (err error) {
	if err = this.validateRecord(tx, db); err != nil {
		return err
	}
	data := tx.Data()
	nlock := &mtypes.NewLockTokenMsg{}
	err = proto.Unmarshal(data, nlock)
	if err != nil {
		return err
	}

	return nil
}

func (this *LockAccountModule)handleLockMsg(header *types.Header, tx *types.Transaction, db *state.StateDB) error {
	if err := this.validateLockMsg(tx, db); err != nil {
		return err
	}
	data := tx.Data()
	lock := &mtypes.LockMsg{}
	if err := proto.Unmarshal(data, lock); err != nil {
		return errors.New("unmarshal data failed")
	}
	signer := types.NewBoeSigner(config.GetHpbConfigInstance().BlockChain.ChainId)
	from,_ := types.Sender(signer,tx)
	return this.ProcessLockMsg(from, lock, db)
}

func (this *LockAccountModule)handleUnLockMsg(header *types.Header, tx *types.Transaction, db *state.StateDB) error {
	if err := this.validateUnlockMsg(tx, db); err != nil {
		return err
	}
	data := tx.Data()
	unlock := &mtypes.UnlockMsg{}
	if err := proto.Unmarshal(data, unlock); err != nil {
		return errors.New("unmarshal data failed")
	}
	signer := types.NewBoeSigner(config.GetHpbConfigInstance().BlockChain.ChainId)
	from,_ := types.Sender(signer,tx)
	return this.ProcessUnLockMsg(header, from, unlock, db)
}