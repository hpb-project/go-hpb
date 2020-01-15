package lockAccount

import (
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"errors"
)

func validateMul(tx *types.Transaction, db *state.StateDB ) error {
	amount := tx.Value().Uint64()
	if amount > 0 {
		return errors.New("Amount must be zero(0)")
	}
	return nil
}


func validateAdd(tx *types.Transaction, db *state.StateDB) error {
	amount := tx.Value().Uint64()
	if amount > 0 {
		return errors.New("Amount must be zero(0)")
	}
	return nil
}
