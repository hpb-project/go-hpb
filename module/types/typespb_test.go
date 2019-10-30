package types

import (
	"encoding/hex"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"testing"
)

func printresult(param *Example) error {
	switch param.Value.(type) {
	case *Example_Mul:
		msm, ok :=param.Value.(*Example_Mul)
		if ok {
			fmt.Printf("ExampleMul a * b = %d\n", msm.Mul.A * msm.Mul.B)
		}
	case *Example_Add:
		msm, ok :=param.Value.(*Example_Add)
		if ok {
			fmt.Printf("ExampleMul a + b = %d\n", msm.Add.A + msm.Add.B)
		}
	}
	return nil
}


func TestExample(t *testing.T) {
	pa := &ParamAdd{A:11,B:21}
	dataA,_ := proto.Marshal(pa)
	fmt.Printf("dataA:%s\n",hex.EncodeToString(dataA))

	pb := &ParamMul{A:11, B:21}
	dataB,_ := proto.Marshal(pb)
	fmt.Printf("dataB:%s\n",hex.EncodeToString(dataB))
	psa := &Example_Add{}
	psa.Add = pa

	psb := &Example_Mul{}
	psb.Mul = pb

	example := &Example{}
	example.Value = psa
	dsa,_ := proto.Marshal(example)
	fmt.Printf("dsa:%s\n", hex.EncodeToString(dsa))
	nsa := &Example{}
	err:=proto.Unmarshal(dsa, nsa)
	if err != nil {
		fmt.Printf("dsa unmarshal to Example failed.\n")
		return
	}
	printresult(nsa)


	example.Value = psb
	dsb,_ := proto.Marshal(example)
	fmt.Printf("dsb:%s\n", hex.EncodeToString(dsb))
	nsb := &Example{}
	err = proto.Unmarshal(dsb, nsb)
	if err != nil {
		fmt.Printf("dsa unmarshal to Example failed.\n")
		return
	}
	printresult(nsb)

}
