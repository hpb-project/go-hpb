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
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"golang.org/x/crypto/ssh/terminal"
)

// config contains all the configurations needed by prometh that should be saved
// between sessions.
type pconfig struct {
	path      string      // File containing the configuration values
	genesis   *bc.Genesis // Genesis block to cache for node deploys
	bootFull  []string    // Bootnodes to always connect to by full nodes
	bootLight []string    // Bootnodes to always connect to by light nodes
	ethstats  string
	Servers   map[string][]byte `json:"servers,omitempty"`
}

// 返回按照字母顺序的服务器
func (c pconfig) servers() []string {
	servers := make([]string, 0, len(c.Servers))
	for server := range c.Servers {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	return servers
}

// 将数据写入到文件中
func (c pconfig) flush() {
	os.MkdirAll(filepath.Dir(c.path), 0755)

	out, _ := json.MarshalIndent(c, "", "  ")
	if err := ioutil.WriteFile(c.path, out, 0644); err != nil {
		log.Warn("Failed to save prometh configs", "file", c.path, "err", err)
	}
}

// prometh 结构体
type prometh struct {
	network string  // Network name to manage
	conf    pconfig // Configurations from previous runs

	servers  map[string]*sshClient // SSH connections to servers to administer
	services map[string][]string   // Hpb services known to be running on servers

	in *bufio.Reader // 处理流文件
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

// readInt reads a single line from stdin, trimming if from spaces, enforcing it
// to parse into an integer.
func (p *prometh) readInt() int {
	for {
		fmt.Printf("> ")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			continue
		}
		val, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			log.Error("Invalid input, expected integer", "err", err)
			continue
		}
		return val
	}
}

// readDefaultInt reads a single line from stdin, trimming if from spaces, enforcing
// it to parse into an integer. If an empty line is entered, the default value is
// returned.
func (p *prometh) readDefaultInt(def int) int {
	for {
		fmt.Printf("> ")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			return def
		}
		val, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil {
			log.Error("Invalid input, expected integer", "err", err)
			continue
		}
		return val
	}
}

// readDefaultBigInt reads a single line from stdin, trimming if from spaces,
// enforcing it to parse into a big integer. If an empty line is entered, the
// default value is returned.
func (p *prometh) readDefaultBigInt(def *big.Int) *big.Int {
	for {
		fmt.Printf("> ")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			return def
		}
		val, ok := new(big.Int).SetString(text, 0)
		if !ok {
			log.Error("Invalid input, expected big integer")
			continue
		}
		return val
	}
}

// readDefaultFloat reads a single line from stdin, trimming if from spaces, enforcing
// it to parse into a float. If an empty line is entered, the default value is returned.
func (p *prometh) readDefaultFloat(def float64) float64 {
	for {
		fmt.Printf("> ")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			return def
		}
		val, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			log.Error("Invalid input, expected float", "err", err)
			continue
		}
		return val
	}
}

// readPassword reads a single line from stdin, trimming it from the trailing new
// line and returns it. The input will not be echoed.
func (p *prometh) readPassword() string {
	fmt.Printf("> ")
	text, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Crit("Failed to read password", "err", err)
	}
	fmt.Println()
	return string(text)
}

// readAddress reads a single line from stdin, trimming if from spaces and converts
// it to an Hpb address.
func (p *prometh) readAddress() *common.Address {
	for {
		// Read the address from the user
		fmt.Printf("> 0x")
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

		/**
				*
				SetString sets z to the value of s, interpreted in the given base, and returns z and a boolean indicating success. The entire string (not just a prefix) must be valid for success. If SetString fails, the value of z is undefined but the returned value is nil.
		        The base argument must be 0 or a value between 2 and MaxBase. If the base is 0, the string prefix determines the actual conversion base. A prefix of “0x” or “0X” selects base 16; the “0” prefix selects base 8, and a “0b” or “0B” prefix selects base 2. Otherwise the selected base is 10.
		*/

		bigaddr, _ := new(big.Int).SetString(text, 16)
		address := common.BigToAddress(bigaddr)
		return &address
	}
}

// readDefaultAddress reads a single line from stdin, trimming if from spaces and
// converts it to an Hpb address. If an empty line is entered, the default
// value is returned.
func (p *prometh) readDefaultAddress(def common.Address) common.Address {
	for {
		// Read the address from the user
		fmt.Printf("> 0x")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			return def
		}
		// Make sure it looks ok and return it if so
		if len(text) != 40 {
			log.Error("Invalid address length, please retry")
			continue
		}
		bigaddr, _ := new(big.Int).SetString(text, 16)
		return common.BigToAddress(bigaddr)
	}
}

// readJSON reads a raw JSON message and returns it.
func (p *prometh) readJSON() string {
	var blob json.RawMessage

	for {
		fmt.Printf("> ")
		if err := json.NewDecoder(p.in).Decode(&blob); err != nil {
			log.Error("Invalid JSON, please try again", "err", err)
			continue
		}
		return string(blob)
	}
}

// readIPAddress reads a single line from stdin, trimming if from spaces and
// returning it if it's convertible to an IP address. The reason for keeping
// the user input format instead of returning a Go net.IP is to match with
// weird formats used by ethstats, which compares IPs textually, not by value.
func (p *prometh) readIPAddress() string {
	for {
		// Read the IP address from the user
		fmt.Printf("> ")
		text, err := p.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text == "" {
			return ""
		}
		// Make sure it looks ok and return it if so
		if ip := net.ParseIP(text); ip == nil {
			log.Error("Invalid IP address, please retry")
			continue
		}
		return text
	}
}
