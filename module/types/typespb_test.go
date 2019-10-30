package types

import (
	"encoding/hex"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"testing"
)

func printresult(param *Sample) error {
	switch param.Value.(type) {
	case *Sample_Mul:
		msm, ok :=param.Value.(*Sample_Mul)
		if ok {
			fmt.Printf("SampleMul a * b = %d\n", msm.Mul.A * msm.Mul.B)
		}
	case *Sample_Add:
		msm, ok :=param.Value.(*Sample_Add)
		if ok {
			fmt.Printf("SampleMul a + b = %d\n", msm.Add.A + msm.Add.B)
		}
	}
	return nil
}


func TestSample(t *testing.T) {
	pa := &ParamAdd{A:11,B:21}
	dataA,_ := proto.Marshal(pa)
	fmt.Printf("dataA:%s\n",hex.EncodeToString(dataA))

	pb := &ParamMul{A:11, B:21}
	dataB,_ := proto.Marshal(pb)
	fmt.Printf("dataB:%s\n",hex.EncodeToString(dataB))
	psa := &Sample_Add{}
	psa.Add = pa

	psb := &Sample_Mul{}
	psb.Mul = pb

	sample := &Sample{}
	sample.Value = psa
	dsa,_ := proto.Marshal(sample)
	fmt.Printf("dsa:%s\n", hex.EncodeToString(dsa))
	nsa := &Sample{}
	err:=proto.Unmarshal(dsa, nsa)
	if err != nil {
		fmt.Printf("dsa unmarshal to sample failed.\n")
		return
	}
	printresult(nsa)


	sample.Value = psb
	dsb,_ := proto.Marshal(sample)
	fmt.Printf("dsb:%s\n", hex.EncodeToString(dsb))
	nsb := &Sample{}
	err = proto.Unmarshal(dsb, nsb)
	if err != nil {
		fmt.Printf("dsa unmarshal to sample failed.\n")
		return
	}
	printresult(nsb)

}
