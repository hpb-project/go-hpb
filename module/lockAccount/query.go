package lockAccount

import (
	"encoding/json"
	"errors"
	"github.com/hpb-project/go-hpb/blockchain/state"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/log"
)

const (
	QueryMethods    	= "methods"
	QueryMethodProjects = "projects"
	QueryMethodRecords	= "records"
)

func (this *LockAccountModule)handleQueryMethods(header *types.Header, db *state.StateDB, data []byte)( string, error) {

	var methods []string
	methods = append(methods, QueryMethods, QueryMethodProjects, QueryMethodRecords)
	ret,err := json.Marshal(methods)
	return string(ret), err
}

type QueryProjects struct{
	a	int `json:"a"`
	b	int `json:"b"`
}

func (this *LockAccountModule)handleQueryProjects(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	param := QueryProjects{}
	if err := json.Unmarshal(data, &param); err != nil {
		return "", errors.New("Unmarshal param failed")
	}
	log.Info("Module example","handleQuery","Projects", "a",param.a, "b", param.b,"result",param.a+param.b)
	result := param.a + param.b

	ret,err := json.Marshal(result)
	return string(ret), err

}

type QueryRecords struct{
	a	int `json:"a"`
	b	int `json:"b"`
}

func (this *LockAccountModule)handleQueryRecords(header *types.Header, db *state.StateDB, data []byte)(string, error) {
	param := QueryRecords{}
	if err := json.Unmarshal(data, &param); err != nil {
		return "", errors.New("Unmarshal param failed")
	}
	log.Info("Module example","handleQuery","Records", "a",param.a, "b", param.b,"result",param.a*param.b)
	result := param.a * param.b

	ret,err := json.Marshal(result)
	return string(ret), err
}
