// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

package prometheus


import (
	"net"
	"time"
	"crypto/sha256"
	"encoding/hex"
	
	"github.com/hpb-project/ghpb/common/log"
	"github.com/hpb-project/ghpb/consensus"

	//"os"
	//"path/filepath"
	//"io/ioutil"
)


func getUniqueRandom(chain consensus.ChainReader) (string){
	hardwareAddr := getHardwareAddr() 
	//monthTimeStamp := getMonthTimeStamp() 
	//uniqueRandom := getSha256(hardwareAddr + monthTimeStamp)
	
	/*
	
	// 支持写入到随机数从文件读取的功能，为了提升效率，目前先从数据库读取
	
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))	
	
    dir = dir +"\\randomData"
	data, err := ioutil.ReadFile(dir)
	if(err != nil) {
		return getSha256(hardwareAddr)
	}
	
	uniqueRandom := string(data[:])
	log.Info("Read random data", "data", uniqueRandom)
	
	if(uniqueRandom ==""){
		uniqueRandom = getSha256(hardwareAddr)
	}
	*/
	
    uniqueRandom := chain.GetRandom()
    if(uniqueRandom == ""){
    	uniqueRandom = getSha256(hardwareAddr)
    	log.Info("Read defaut random data", "data", uniqueRandom)
    }else{
    	log.Info("Read customized random data", "data", uniqueRandom)
    }
	return uniqueRandom
}

func getSha256(str string) (string){
	sha_256 := sha256.New()
	sha_256.Write([]byte(str))
	
	return hex.EncodeToString(sha_256.Sum(nil))
}

func getHardwareAddr() (string){
	interfaces, err := net.Interfaces()
	if err != nil {
		panic("Error:" + err.Error())
	}
	return interfaces[0].HardwareAddr.String()
}

func getMonthTimeStamp() (string){
	return time.Now().Month().String()
}