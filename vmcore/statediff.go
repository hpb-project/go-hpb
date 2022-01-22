package vmcore

import (
	"encoding/json"
	"github.com/hpb-project/go-hpb/common"
)

type State_Diff struct {
	From     common.Address //transfer from address
	To       common.Address //transfer to address
	Tvalue   string         //transfer value
	Gaslimit uint64         //transfer gaslimit
	Depth    int            //vm depth
	Id       int            //vm transfer counts
}

func (statediff State_Diff) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"from":     statediff.From,
		"to":       statediff.To,
		"value":    statediff.Tvalue,
		"gaslimit": statediff.Gaslimit,
		"depth":    statediff.Depth,
		"id":       statediff.Id,
	})
}
