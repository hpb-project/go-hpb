package example

import (
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
)

const (
	QueryMethods    = "methods"
)

func handleQueryMethods(header *types.Header, db *state.StateDB, data []byte)(res []byte, error) {
	return []byte(QueryMethods), nil
}