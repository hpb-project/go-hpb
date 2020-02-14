package lockAccount

import (
	"github.com/gogo/protobuf/proto"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	mtypes "github.com/hpb-project/go-hpb/module/types"
)

func (this *LockAccountModule) handleNewProject(header *types.Header, tx *types.Transaction, db *state.StateDB ) (err error) {
	data := tx.Data()
	npro := &mtypes.NewLockProjectMsg{}
	err = proto.Unmarshal(data, npro)
	if err != nil {
		return err
	}

	return nil
}


func (this *LockAccountModule)handleNewLockToken(header *types.Header, tx *types.Transaction, db *state.StateDB) (err error) {
	data := tx.Data()
	nlock := &mtypes.NewLockTokenMsg{}
	err = proto.Unmarshal(data, nlock)
	if err != nil {
		return err
	}

	return nil
}