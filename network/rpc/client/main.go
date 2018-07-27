package main

import (
	"bytes"
	"encoding/json"
	"time"
	"net/http"
	"strings"
	"io/ioutil"

	"github.com/hpb-project/go-hpb/common/log"
)

func  send(url string, data string, client http.Client)  {

	req, _ := http.NewRequest("POST", url, strings.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		panic(err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	log.Info("Response ","Body", bytes.NewBuffer(body).String())
}





func main() {
	url    := "http://127.0.0.1:28451"
	client := &http.Client{}

	request := hpb_sendTransaction("0xb43557693992362c1cf2a4aba13edad2804160bf", "0x4892ed9c786212d9bd14e8c81811f260418cf6c5","0x1010",100)


	t1 :=time.Now()
	send(url, request, *client)
	t2 :=time.Now()
	delay :=t2.Sub(t1).Nanoseconds()/1000000
	log.Info("Send rpc by millisecond.","delay",delay)

}


///////////////////////////////////////////////////////////////

type Tx struct {
	From  string   `json:"from"`
	To    string   `json:"to"`
	Value string   `json:"value"`
}

type Transaction struct {
	Txs      []Tx	`json:"params"`
	Id       int    `json:"id"`
	Jsonrpc  string `json:"jsonrpc"`
	Method   string `json:"method"`

}
func hpb_sendTransaction(from string, to string, val string,times int) string {
	transaction  := make([]interface{},0,times)
	for i:=0; i<times; i++{
		txs := []Tx{{from,to,val}}
		transaction = append(transaction, Transaction{Txs:txs, Method:"hpb_sendTransaction",Jsonrpc:"2.0",Id:1})
	}
	b,_:= json.Marshal(transaction)
	return string(b)
}

