package event

import (
	"github.com/hpb-project/go-hpb/types"
)

type ChainHeadEvent struct {
	Message *types.Block
}

type TxPreEvent struct {
	Message *types.Transaction
}
