package iperf3

import (
	"os/exec"
	"bytes"
	"fmt"
	"bufio"
	"io"
	"github.com/hpb-project/go-hpb/common/log"
	"strings"
	"encoding/json"
	"os"
)

func exec_shell(s string) (string, error){
	var out bytes.Buffer
	cmd := exec.Command("/bin/bash", "-c", s)

	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func IperfServer() string {
	cmd := exec.Command("/bin/bash", "-c", "./iperf3 -s -p 5188")
	fmt.Println(cmd.Args)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	cmd.Start()
	reader := bufio.NewReader(stdout)
	var count uint64
	for {
		line, err2 := reader.ReadString('\n')
		if err2 != nil || io.EOF == err2 {
			break
		}

		count = count +1
		fmt.Println(line)
		log.Info("Read","Num",count,"Out",line)
	}
	cmd.Wait()
	log.Info("Over End.")
	return "Over"
}

func StartSever(port int) (error) {

	cmd := exec.Command("./iperf3", " -s ", " -p "+string(port))
	stdout, err := os.OpenFile("./iperf_server.log", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error("open iperf_server.log","err",err)
		return err

	}
	defer stdout.Close()
	cmd.Stdout = stdout

	if err := cmd.Start(); err != nil {
		log.Error("start iperf server","err",err)
		return err
	}

	return nil
}

func StartTest(host string, port string) (float64) {
	result,_ :=exec_shell("./iperf3 -c "+host+" -p "+port +"-t 10 -J")

	if !strings.Contains(result, "bits_per_second"){
		log.Warn("Test string in not right.")
		return 0
	}

	var dat map[string]interface{}
	json.Unmarshal([]byte(result), &dat)

	sum:= dat["end"].(map[string]interface{})

	sum_sent     := sum["sum_sent"].(map[string]interface{})
	sum_received := sum["sum_received"].(map[string]interface{})

	send := sum_sent["bits_per_second"].(float64)
	recv := sum_received["bits_per_second"].(float64)
	log.Debug("iperf test result","sendrate",send, "recvrate",recv,"avg",(send+recv)/2)
	return  (send+recv)/2
}
