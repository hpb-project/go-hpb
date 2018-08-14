package iperf3

import (
	"testing"
)

func TestClient(t *testing.T) {

	//cmd := exec.Command("/bin/bash", "-c", "./iperf3 -s -p 5188")
	//
	//stdout, err := cmd.StdoutPipe()
	//if err != nil {
	//	return
	//}
	//
	//cmd.Start()
	//reader := bufio.NewReader(stdout)
	////实时循环读取输出流中的一行内容
	//var count uint64
	//for {
	//	line, err2 := reader.ReadString('\n')
	//	if err2 != nil{
	//		//break
	//	}
	//	count = count +1
	//	//fmt.Println(line)
	//	t.Error("Read","Num",count,"Out",line,"err",err2)
	//}
	//cmd.Wait()
	//t.Error("Over End.")
	//return

	//out,err :=exec_shell("./iperf3 -c 127.0.0.1 -p 5188 -t 10")
	//t.Error("TestClient","out",out,"err",err)

	//out :=StartTest("127.0.0.1","5188")
	StartSever(5188)
	//t.Error(out)
}