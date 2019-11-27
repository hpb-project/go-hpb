package example

import (
	"encoding/json"
	"errors"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/log"
)

const (
	QueryMethods    = "methods"
	QueryMethodAdd		= "add"
	QueryMethodMul		= "mul"
)

func handleQueryMethods(header *types.Header, db *state.StateDB, data []byte)( string, error) {

	var methods []string
	methods = append(methods, QueryMethods, QueryMethodAdd, QueryMethodMul)
	ret,err := json.Marshal(methods)
	return string(ret), err
}

type QueryAdd struct{
	a	int `json:"a"`
	b	int `json:"b"`
}

func handleQueryAdd(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	param := QueryAdd{}
	if err := json.Unmarshal(data, &param); err != nil {
		return "", errors.New("Unmarshal param failed")
	}
	log.Info("Module example","handleQuery","Add", "a",param.a, "b", param.b,"result",param.a+param.b)
	result := param.a + param.b

	ret,err := json.Marshal(result)
	return string(ret), err

}

type QueryMul struct{
	a	int `json:"a"`
	b	int `json:"b"`
}

func handleQueryMul(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	param := QueryAdd{}
	if err := json.Unmarshal(data, &param); err != nil {
		return "", errors.New("Unmarshal param failed")
	}
	log.Info("Module example","handleQuery","Mul", "a",param.a, "b", param.b,"result",param.a*param.b)
	result := param.a * param.b

	ret,err := json.Marshal(result)
	return string(ret), err

}
