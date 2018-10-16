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
// along with the go-hpb. If not, see <http://wwp.gnu.org/licenses/>.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	//"strconv"
	"strings"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	//"golang.org/x/crypto/ssh/terminal"
)

type config struct {
	path    string      // File containing the configuration values
	genesis []CadWinner // Genesis block to cache for node deploys
}

// 将数据写入到文件中
func (c config) flush() {
	os.MkdirAll(filepath.Dir(c.path), 0755)

	out, _ := json.MarshalIndent(c, "", "  ")
	if err := ioutil.WriteFile(c.path, out, 0644); err != nil {
		log.Warn("Failed to save prometh configs", "file", c.path, "err", err)
	}
}

// prometh 结构体
type prometh struct {
	network string        // Network name to manage
	conf    config        // Configurations from previous runs
	in      *bufio.Reader // 处理流文件
}

// read reads a single line from stdin, trimming if from spaces.
func (p *prometh) read() string {
	fmt.Printf("> ")
	text, err := p.in.ReadString('\n')
	if err != nil {
		log.Crit("Failed to read user input", "err", err)
	}
	return strings.TrimSpace(text)
}

// readAddress reads a single line from stdin, trimming if from spaces and converts
// it to an Hpb address.
func (p *prometh) readAddress() *common.Address {
	for {
		// Read the address from the user
		fmt.Printf("> hpb")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			return nil
		}

		// Make sure it looks ok and return it if so
		if len(text) != 40 {
			log.Error("Invalid address length, please retry")
			continue
		}

		bigaddr, _ := new(big.Int).SetString(text, 16)
		address := common.BigToAddress(bigaddr)
		return &address
	}
}

// readString reads a single line from stdin, trimming if from spaces, enforcing
// non-emptyness.
func (p *prometh) readString() string {
	for {
		fmt.Printf("> ")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text != "" {
			return text
		}
	}
}

// readDefaultString reads a single line from stdin, trimming if from spaces. If
// an empty line is entered, the default value is returned.
func (p *prometh) readDefaultString(def string) string {
	fmt.Printf("> ")
	text, err := p.in.ReadString('\n')
	if err != nil {
		log.Crit("Failed to read user input", "err", err)
	}
	if text = strings.TrimSpace(text); text != "" {
		return text
	}
	return def
}
