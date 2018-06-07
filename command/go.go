package main

import (
    "fmt"
    //"reflect"
	//"sync"

	"bytes"
	"strconv"
	"encoding/json"
	//"io/ioutil"
	"time"
	//"github.com/jmcvetta/napping"
	"runtime"
	"net/http"
    "strings"

)

type MyStruct struct {
    name string
}

func (this *MyStruct) GetName(str string) string {
    this.name = str
    return this.name
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
		fmt.Println(fmt.Sprintf("%02X", v))
	}

	ss := strings.Join(sa, "")
	return ss
}

func ByteToHex(data []byte) string {
	buffer := new(bytes.Buffer)
	for _, b := range data {
		s := strconv.FormatInt(int64(b&0xff), 16)
		if len(s) == 1 {
			buffer.WriteString("0")
		}
		buffer.WriteString(s)
	}

	return buffer.String()
}
//param =  {
//"from": "0xff724f1497ecbb6fbc34773baedce17a75bc16c3",
//"to": "0x777c759983a55b7eb85300687c1f16e12b34f2b7"
//}
type Tx struct {

	From  string   `json:"from"`

	To  string `json:"to"`

	Value string   `json:"value"`

}
type Data struct {
	Txs []Tx	`json:"params"`

	Id  int   `json:"id"`

	Jsonrpc  string `json:"jsonrpc"`

	Method string   `json:"method"`

}

func  send(url string,data string,c http.Client)  {
	//fmt.Println(data)

	req, _ := http.NewRequest("POST", url, strings.NewReader(data))
	//
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	//defer wg.Add(-1)
	//body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println("response Body:", bytes.NewBuffer(body).String() )
}
//var wg sync.WaitGroup
func main() {



    // 备注: reflect.Indirect -> 如果是指针则返回 Elem()
    // 首先，reflect包有两个数据类型我们必须知道，一个是Type，一个是Value。
    // Type就是定义的类型的一个数据类型，Value是值的类型
	url := "http://127.0.0.1:8545"
	//
	////var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)


	//tx_.Value ="0xc6"

	//if err!=nil{
	//	println(err)
	//}
	maxProcs := runtime.NumCPU()
	fmt.Println("cpu_count :",maxProcs)

	//runtime.GOMAXPROCS(200)


	c := &http.Client{}
	datas := make([]interface{},0)
	num :=float64(11)
	for i:=1;i<int(num);i++{
		ss:=Data{}
		ss.Method = "hpb_sendTransaction"
		ss.Jsonrpc ="2.0"
		ss.Id = 67
		tx_ :=Tx{}
		tx_.From = "0xcd06f5eae109e6d5d06222b02ccefdcbefbeb997"
		tx_.To = "0x7b6b42805b9f46183c22a68393599cd7246bacaa"
		//wg.Add(1)
		bb := byte(i*100)
		vv := ByteToHex([]byte{bb})
		//fmt.Println(vv)
		tx_.Value = "0x"+string(vv)

		ss.Txs = append(ss.Txs,tx_)
		datas = append(datas, ss)
		//send(url,string(b))
	}
	//wg.Wait()

	b,_:= json.Marshal(datas)
	t1 :=time.Now()
	//nnn :=300
	//for ;;nnn = nnn+300 {
		send(url,string(b),*c)
		//fmt.Println("all send until now :",nnn)
		//time.Sleep(5*time.Second)
	//}
	

	t2 :=time.Now()
	dd :=t2.Sub(t1).Seconds()
	dd1 :=t2.Sub(t1).Nanoseconds()
	fmt.Println(dd,"/s")
	fmt.Println(dd1,"/Nanoseconds")
	fmt.Println(num/dd,"counts/s")
	//
	//body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println("response Body:", bytes.NewBuffer(body).String() )

	//v := "ff"
	//arr := []int{1,3,5,3,3,5}
	//fmt.Println(arr[1:3])
	//s, _:= strconv.ParseUint(v, 16, 8)
	//fmt.Println("")
	//fmt.Printf("%T|%d|\n", v, s)

	//// 对象
	//s := "this is string"
	//
	//// 获取对象类型 (string)
	//fmt.Println(reflect.TypeOf(s))
	//
	//// 获取对象值 (this is string)
	//fmt.Println(reflect.ValueOf(s))
	//
	//
	//// 对象
	//a := &MyStruct{name: "nljb"}
	//fmt.Println(reflect.ValueOf(a))
	//fmt.Println(reflect.TypeOf(a))
}