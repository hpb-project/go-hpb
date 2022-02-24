package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

type Group struct {
	R      string `json:"r"`
	S      string `json:"s"`
	H      string `json:"h"`
	X      string `json:"x"`
	Y      string `json:"y"`
	V      int    `json:"v"`
	msg    []byte `json:"-"`
	sig    []byte `json:"-"`
	pubkey []byte `json:"-"`
}

func copyBytes(src []byte) []byte {
	if src != nil && len(src) > 0 {
		dest := make([]byte, len(src))
		copy(dest, src)
		return dest
	}
	return []byte{}
}
func (g *Group) Copy() *Group {
	newg := &Group{}
	newg.R = g.R
	newg.S = g.S
	newg.H = g.H
	newg.X = g.X
	newg.Y = g.Y
	newg.V = g.V
	newg.msg = copyBytes(g.msg)
	newg.sig = copyBytes(g.sig)
	newg.pubkey = copyBytes(g.pubkey)
	return newg
}

func paddingLeft(hexstr string, length int) string {
	var str = hexstr
	for len(str) < length {
		str = "0" + str
	}
	return str
}

func changeToTask(g *Group) {
	g.msg, _ = hex.DecodeString(paddingLeft(g.H, 64))
	g.sig, _ = hex.DecodeString(paddingLeft(g.R, 64) + paddingLeft(g.S, 64))
	g.sig = append(g.sig, byte(g.V))
	g.pubkey, _ = hex.DecodeString(paddingLeft(g.X, 64) + paddingLeft(g.Y, 64))
}

func loadData(filename string, count int) ([]*Group, error) {
	fi, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return nil, err
	}
	defer fi.Close()
	var groups = make([]*Group, 0, count)

	br := bufio.NewReader(fi)
	for len(groups) < count {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		var g Group
		if e := json.Unmarshal(a, &g); e == nil {
			changeToTask(&g)
			groups = append(groups, &g)
		}
	}
	if len(groups) < count {
		for i := 0; len(groups) < count; i++ {
			ng := groups[i].Copy()
			groups = append(groups, ng)
		}
	}

	log.Printf("load data %d.\n", len(groups))

	return groups, nil
}
