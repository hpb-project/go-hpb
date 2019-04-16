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

package p2p

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"math/big"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errClosed        = errors.New("peer set is closed")
	errNotRegistered = errors.New("peer is not registered")
	errIncomplete    = errors.New("PeerManager is incomplete creation")
)

const (
	maxKnownTxs    = 1000000 // Maximum transactions hashes to keep in the known list (prevent DOS)
	maxKnownBlocks = 100000  // Maximum block hashes to keep in the known list (prevent DOS)
)

type PeerManager struct {
	peers  map[string]*Peer
	boots  map[string]*Peer
	lock   sync.RWMutex
	closed bool

	server *Server
	hpbpro *HpbProto

	ilock   sync.Mutex
	iport   int
	isrvcmd *exec.Cmd
	isrvout *os.File
}

var INSTANCE = atomic.Value{}

func PeerMgrInst() *PeerManager {
	if INSTANCE.Load() == nil {
		pm := &PeerManager{
			peers:  make(map[string]*Peer),
			boots:  make(map[string]*Peer),
			server: &Server{},
			hpbpro: NewProtos(),
		}
		INSTANCE.Store(pm)
	}

	return INSTANCE.Load().(*PeerManager)
}

func (prm *PeerManager) Start(coinbase common.Address) error {

	config := config.GetHpbConfigInstance()

	prm.server.Config = Config{
		NAT:        config.Network.NAT,
		Name:       config.Network.Name,
		TestMode:   config.Node.TestMode == 1,
		PrivateKey: config.Node.PrivateKey,
		NetworkId:  config.Node.NetworkId,
		ListenAddr: config.Network.ListenAddr,

		NetRestrict:     config.Network.NetRestrict,
		NodeDatabase:    config.Network.NodeDatabase,
		BootstrapNodes:  config.Network.BootstrapNodes,
		EnableMsgEvents: config.Network.EnableMsgEvents,

		Protocols: prm.hpbpro.Protocols(),
	}

	prm.server.Config.CoinBase = coinbase
	log.Info("Set coinbase address by start", "address", coinbase.String(), "roletype", config.Network.RoleType)
	if config.Network.RoleType != "synnode" {
		if coinbase.String() == "0x0000000000000000000000000000000000000000" {
			panic("coinbase address is nil.")
		}
	}
	prm.hpbpro.networkId = prm.server.NetworkId
	prm.hpbpro.regMsgProcess(ReqNodesMsg, HandleReqNodesMsg)
	prm.hpbpro.regMsgProcess(ResNodesMsg, HandleResNodesMsg)

	prm.hpbpro.regMsgProcess(ReqBWTestMsg, prm.HandleReqBWTestMsg)
	prm.hpbpro.regMsgProcess(ResBWTestMsg, prm.HandleResBWTestMsg)

	prm.hpbpro.regMsgProcess(ReqRemoteStateMsg, HandleReqRemoteStateMsg)
	prm.hpbpro.regMsgProcess(ResRemoteStateMsg, HandleResRemoteStateMsg)


	copy(prm.server.Protocols, prm.hpbpro.Protocols())

	localType := discover.PreNode
	if config.Network.RoleType == "bootnode" {
		localType = discover.BootNode
	} else if config.Network.RoleType == "synnode" {
		localType = discover.SynNode
	}
	prm.SetLocalType(localType)
	log.Info("Set Init Local Type by p2p", "type", localType.ToString())

	if err := prm.server.Start(); err != nil {
		log.Error("Hpb protocol", "error", err)
		return err
	}
	////////////////////////////////////////////////////////////////////////////////////////
	//for bootnode check
	self := prm.server.Self()
	for _, n := range config.Network.BootstrapNodes {
		if self.ID == n.ID && prm.server.localType != discover.BootNode {
			panic("Need BOOTNODE flag.")
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////
	add, _ := net.ResolveUDPAddr("udp", prm.server.ListenAddr)
	prm.iport = add.Port + 100
	log.Debug("Iperf server start", "port", prm.iport)
	prm.startServerBW(strconv.Itoa(prm.iport))

	if prm.server.localType != discover.BootNode && prm.server.localType != discover.SynNode {
		go prm.startClientBW()
	}

	/////////////////////////////////////////////////////////////////////////////////////////
	//for bing info
	if prm.server.localType == discover.BootNode {
		filename := filepath.Join(config.Node.DataDir, bindInfoFileName)
		log.Debug("bootnode load bindings", "filename", filename)
		prm.parseBindInfo(filename)
	}

	return nil
}

func (prm *PeerManager) Stop() {
	prm.server.Stop()
	prm.server = nil

	prm.close()

	prm.isrvout.Close()
	prm.isrvcmd.Process.Kill()
}

func (prm *PeerManager) P2pSvr() *Server {
	return prm.server
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
func (prm *PeerManager) Register(p *Peer) error {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	if prm.closed {
		return errClosed
	}
	if p.remoteType == discover.BootNode {
		if _, ok := prm.boots[p.id]; !ok {
			prm.boots[p.id] = p
			log.Debug("Peer with bootnode is listed.")
		}
		return nil
	}

	if _, ok := prm.peers[p.id]; ok {
		return DiscAlreadyConnected
	}
	prm.peers[p.id] = p
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (prm *PeerManager) unregister(id string) error {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	if _, ok := prm.peers[id]; ok {
		delete(prm.peers, id)
	}

	if _, ok := prm.boots[id]; ok {
		delete(prm.boots, id)
	}

	return nil
}

// Peer retrieves the registered peer with the given id.
func (prm *PeerManager) Peer(id string) *Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	return prm.peers[id]
}

func (prm *PeerManager) DefaultAddr() common.Address {
	return prm.server.CoinBase
}

func (prm *PeerManager) PeersAll() []*Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	list := make([]*Peer, 0, len(prm.peers))
	for _, p := range prm.peers {

		//if p.remoteType == discover.SynNode {
		//	continue
		//}

		list = append(list, p)
	}
	return list
}

func (prm *PeerManager) GetLocalType() discover.NodeType {
	return prm.server.localType
}

func (prm *PeerManager) SetLocalType(nt discover.NodeType) bool {
	log.Info("Change node local type", "from", prm.server.localType.ToString(), "to", nt.ToString())

	//if prm.server.localType == discover.SynNode {
	//	log.Info("SynNode need not allow to change", "to", nt.ToString())
	//	return true
	//}


	if prm.server.localType != nt {
		prm.lock.Lock()
		defer prm.lock.Unlock()

		prm.server.localType = nt
		for _, p := range prm.peers {
			p.localType = nt
		}
		return true
	}

	return false
}

/*
func (prm *PeerManager) SetHpRemoteFlag(flag bool) {
	//log.Info("Change hp remote flag","from",prm.server.hpflag,"to",flag)
	if prm.server.hpflag != flag {
		prm.server.hpflag = flag
	}
}
*/
// Len returns if the current number of peers in the set.
func (prm *PeerManager) Len() int {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	return len(prm.peers)
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (prm *PeerManager) PeersWithoutBlock(hash common.Hash) []*Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	list := make([]*Peer, 0, len(prm.peers))
	for _, p := range prm.peers {
		if !p.knownBlocks.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (prm *PeerManager) PeersWithoutTx(hash common.Hash) []*Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	list := make([]*Peer, 0, len(prm.peers))
	for _, p := range prm.peers {
		if !p.knownTxs.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (prm *PeerManager) BestPeer() *Peer {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	var (
		bestPeer *Peer
		bestTd   *big.Int
	)
	for _, p := range prm.peers {
		if p.remoteType == discover.SynNode {
			continue
		}

		if p.msgLooping == false {
			continue
		}

		if _, td := p.Head(); bestPeer == nil || td.Cmp(bestTd) > 0 {
			bestPeer, bestTd = p, td
		}
	}
	return bestPeer
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (prm *PeerManager) close() {
	prm.lock.Lock()
	defer prm.lock.Unlock()

	for _, p := range prm.peers {
		p.Disconnect(DiscQuitting)
	}
	prm.closed = true
}

func (prm *PeerManager) Protocol() []Protocol {
	return prm.hpbpro.protos
}

//func (prm *PeerManager) hasPeer(id string) bool {
//	prm.lock.RLock()
//	defer prm.lock.RUnlock()
//
//	return prm.boots[id] != nil || prm.peers[id] !=nil
//}
////////////////////////////////////////////////////////////////////

type PeerInfo struct {
	ID      string `json:"id"`     // Unique node identifier (also the encryption key)
	Name    string `json:"name"`   // Name of the node, including client type, version, OS, custom data
	Version string `json:"version"`// Ghpb version
	Remote  string `json:"remote"` // Remote node type
	Cap     string `json:"cap"`    // Sum-protocols advertised by this particular peer
	Network struct {
		Local  string `json:"local"`  // Local endpoint of the TCP data connection
		Remote string `json:"remote"` // Remote endpoint of the TCP data connection
	} `json:"network"`
	Start   string      `json:"start"` //
	Beat    string      `json:"beat"`  //
	Mining  string      `json:"mining"`  //
	HPB   interface{} `json:"hpb"`   // Sub-protocol specific metadata fields
}

type HpbInfo struct {
	TD      *big.Int `json:"handshakeTD"` // Total difficulty of the peer's blockchain
	Head    string   `json:"handshakeHD"` // SHA3 hash of the peer's best owned block
}

func (prm *PeerManager) PeersInfo() []*PeerInfo {
	prm.lock.RLock()
	defer prm.lock.RUnlock()

	req := statusRes{Version:0x01}
	req.Status = append(req.Status, StatDetail{0x00, ""})
	for _, p := range prm.peers {
		if p.remoteType == discover.PreNode || p.remoteType == discover.HpNode {
			SendData(p,ReqRemoteStateMsg,req)
		}
	}
	time.Sleep(time.Second)


	allinfos := make([]*PeerInfo, 0, len(prm.boots)+len(prm.peers))
	for _, p := range prm.boots {
		info := &PeerInfo{
			ID:     p.ID().TerminalString(),
			Name:   p.Name(),
			Version:p.Version(),
			Remote: p.remoteType.ToString(),
			Cap:    p.Caps()[0].String(),
			Start:  p.beatStart.String(),
			Beat:   strconv.FormatUint(p.count, 10),
			Mining: p.statMining,
			HPB:    "",
		}
		info.Network.Local = p.LocalAddr().String()
		info.Network.Remote = p.RemoteAddr().String()

		allinfos = append(allinfos, info)
	}

	peerinfos := make([]*PeerInfo, 0, len(prm.peers))
	for _, p := range prm.peers {
		hash, td := p.Head()
		info := &PeerInfo{
			ID:     p.ID().TerminalString(),
			Name:   p.Name(),
			Version:p.Version(),
			Remote: p.remoteType.ToString(),
			Cap:    p.Caps()[0].String(),
			Start:  p.beatStart.String(),
			Beat:   strconv.FormatUint(p.count, 10),
			Mining: p.statMining,
			HPB: &HpbInfo{
				TD:      td,
				Head:    hash.Hex(),
			},
		}
		info.Network.Local = p.LocalAddr().String()
		info.Network.Remote = p.RemoteAddr().String()
		peerinfos = append(peerinfos, info)
	}

	for i := 0; i < len(peerinfos); i++ {
		for j := i + 1; j < len(peerinfos); j++ {
			if peerinfos[i].ID > peerinfos[j].ID {
				peerinfos[i], peerinfos[j] = peerinfos[j], peerinfos[i]
			}
		}
	}
	allinfos = append(allinfos, peerinfos...)

	return allinfos
}

type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Local string `json:"local"` // Local node type
	IP    string `json:"ip"`    // IP address of the node
	Ports struct {
		UDP int `json:"udp"` // UDP listening port for discovery protocol
		TCP int `json:"tcp"` // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string `json:"listenAddr"`
}

func (prm *PeerManager) NodeInfo() *NodeInfo {
	node := prm.server.Self()

	info := &NodeInfo{
		Name:       prm.server.Name,
		Local:      prm.server.localType.ToString(),
		ID:         node.ID.String(),
		IP:         node.IP.String(),
		ListenAddr: prm.server.ListenAddr,
	}
	info.Ports.UDP = int(node.UDP)
	info.Ports.TCP = int(node.TCP)

	return info
}

////////////////////////////////////////////////////////////////////
func (prm *PeerManager) RegMsgProcess(msg uint64, cb MsgProcessCB) {
	prm.hpbpro.regMsgProcess(msg, cb)
	return
}

func (prm *PeerManager) RegChanStatus(cb ChanStatusCB) {
	prm.hpbpro.regChanStatus(cb)
	log.Debug("ChanStatus has been register")
	return
}

func (prm *PeerManager) RegOnAddPeer(cb OnAddPeerCB) {
	prm.hpbpro.regOnAddPeer(cb)
	log.Debug("OnAddPeer has been register")
	return
}

func (prm *PeerManager) RegOnDropPeer(cb OnDropPeerCB) {
	prm.hpbpro.regOnDropPeer(cb)
	log.Debug("OnDropPeer has been register")
	return
}

func (prm *PeerManager) RegStatMining(cb StatMining) {
	prm.hpbpro.regStatMining(cb)
	log.Debug("StatMining has been register")
	return
}
////////////////////////////////////////////////////////////////////
const bindInfoFileName = "binding.json"

type bindInfo struct {
	CID string `json:"cid"`
	HID string `json:"hid"`
	ADR string `json:"coinbase"`
}

type HwPair struct {
	Adr string
	Cid []byte
	Hid []byte
}

func (prm *PeerManager) GetHwInfo() []HwPair {
	return prm.server.getHdtab()
}

func (prm *PeerManager) SetHwInfo(pairs []HwPair) error {
	return prm.server.updateHdtab(pairs,false)
}

func (prm *PeerManager) parseBindInfo(filename string) error {
	// Load the nodes from the config file.
	var binding []bindInfo
	if err := common.LoadJSON(filename, &binding); err != nil {
		log.Error(fmt.Sprintf("Can't load node file %s: %v", filename, err))
		panic("Hardware Info Parse Error. Can't load node file.")
	}
	log.Debug("Boot node parse binding hardware table.", "binding", binding)
	hdtab := make([]HwPair, 0, len(binding))
	for i, b := range binding {
		cid, cerr := hex.DecodeString(b.CID)
		hid, herr := hex.DecodeString(b.HID)
		if cerr != nil || herr != nil {
			log.Error(fmt.Sprintf("Can't parse node file %s(index=%d)", filename,i))
			panic("Hardware Info Parse Error.")
		}
		//todo check cid hid adr
		hdtab = append(hdtab, HwPair{Adr: strings.ToLower(b.ADR), Cid: cid, Hid: hid})
	}


	log.Info("Boot node parse binding hardware table.", "hdtab", hdtab)
	prm.server.updateHdtab(hdtab,true)
	//prm.server.hdtab = hdtab

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
func (prm *PeerManager) startServerBW(port string) error {
	/////////////////////////////////////
	//for iperf test
	hpbbin, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	ipfbin := filepath.Join(hpbbin, "iperf3")

	if flag, err := exists(ipfbin); err != nil || flag == false {
		log.Error("Iperf3 should exist in correct dir.", "Path", ipfbin)
		panic("Iperf3 should exist in correct dir.")
	}

	//server
	var err error
	logName := "iperf_server_" + port + ".log"
	logName = filepath.Join(hpbbin, logName)
	prm.isrvout, err = os.OpenFile(logName, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error("Open iperf log file", "file", logName, "err", err)
		panic("Can not open iperf log file")
		return err
	}

	cmd := ipfbin + " -s -p " + port
	prm.isrvcmd = exec.Command("/bin/bash", "-c", cmd)
	prm.isrvcmd.Stdout = prm.isrvout

	if err := prm.isrvcmd.Start(); err != nil {
		log.Error("Start iperf server", "err", err)
		panic("Can not start iperf server")
		return err
	}

	log.Info("Start server of bandwidth test.", "port", port)
	return nil
}

func (prm *PeerManager) startTest(host string, port string) float64 {
	hpbbin, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	ipfbin := filepath.Join(hpbbin, "iperf3")

	cmd := ipfbin + " -J -c " + host + " -p " + port + " -t 5"
	result, _ := exec_shell(cmd)

	if !strings.Contains(result, "bits_per_second") {
		log.Warn("Test string in not right.", "host", host, "port", port)
		return 0
	}

	var dat map[string]interface{}
	json.Unmarshal([]byte(result), &dat)

	sum := dat["end"].(map[string]interface{})

	sum_sent := sum["sum_sent"].(map[string]interface{})
	sum_received := sum["sum_received"].(map[string]interface{})

	send := sum_sent["bits_per_second"].(float64)
	recv := sum_received["bits_per_second"].(float64)
	log.Debug("iperf test result", "sendrate", send, "recvrate", recv, "avg", (send+recv)/2)
	return (send + recv) / 2
}

func (prm *PeerManager) startClientBW() {
	/////////////////////////////////////
	//client
	inteval := 60 * 60 // second of one hour
	rand.Seed(time.Now().UnixNano())
	timeout := time.NewTimer(time.Second * time.Duration(inteval+rand.Intn(inteval)))
	defer timeout.Stop()

	for {
		//1 start to test
		//log.Info("waiting start test")
		select {
		case <-timeout.C:
			timeout.Reset(time.Second * time.Duration(inteval+rand.Intn(inteval)))
		}

		//2 select peer to test
		if len(prm.peers) == 0 {
			log.Warn("There is no peer to start bandwidth testing.")
			continue
		}

		pzlist := make([]*Peer, 0, len(prm.peers))
		palist := make([]*Peer, 0, len(prm.peers))
		for _, p := range prm.peers {
			//bandwidth
			//p.log.Error("############ select peer to bw test","bandwidth",p.bandwidth)
			if p.remoteType == discover.BootNode || p.remoteType == discover.SynNode {
				continue
			}
			p.log.Debug("select peer to bw test", "bandwidth", p.bandwidth)
			palist = append(palist, p)
			if p.bandwidth < 0.1 {
				pzlist = append(pzlist, p)
			}
		}

		if len(palist) == 0 {
			log.Warn("There is no hpnode or prenode peer to start bandwidth testing.")
			continue
		}

		//3. do test
		if len(pzlist) > 0 {
			pt := pzlist[0]
			pt.log.Debug("Start bandwidth testing(first).", "remoteType", pt.remoteType.ToString())
			prm.sendReqBWTestMsg(pt)
			timeout.Reset(time.Second * time.Duration(inteval+rand.Intn(inteval)))
			continue
		}

		skip := rand.Intn(len(palist))
		for _, p := range palist {
			if skip > 0 {
				skip = skip - 1
				continue
			}

			p.log.Debug("Start bandwidth testing.", "remoteType", p.remoteType.ToString())
			prm.sendReqBWTestMsg(p)
			break
		}
		log.Debug("Reset timeout to longer.")
		timeout.Reset(time.Second * time.Duration(inteval*2+rand.Intn(inteval*2)))
	}
	log.Error("Test bandwidth loop stop.")
	return
}

type bwTestRes struct {
	Version uint64
	Port    uint16
	Allowed uint16
	Expir   uint64
}

func (prm *PeerManager) sendReqBWTestMsg(p *Peer) {
	if err := SendData(p, ReqBWTestMsg, struct{}{}); err != nil {
		log.Error("Send req bandwidth test msg.", "error", err)
	}

	return
}

func (prm *PeerManager) HandleReqBWTestMsg(p *Peer, msg Msg) error {
	go func() {
		prm.ilock.Lock()
		defer prm.ilock.Unlock()

		p.log.Debug("Lock of iperf server.")
		resp := bwTestRes{
			Version: 0x01,
			Port:    uint16(prm.iport),
			Allowed: 0xff,
			Expir:   uint64(time.Now().Add(time.Second * 5).Unix()),
		}
		if err := SendData(p, ResBWTestMsg, &resp); err != nil {
			p.log.Warn("Send ResBWTestMsg msg error.", "error", err)
			return
		}

		time.Sleep(time.Second * 15)
		p.log.Debug("Release lock of iperf server.")
	}()

	return nil
}

func (prm *PeerManager) HandleResBWTestMsg(p *Peer, msg Msg) error {
	var request bwTestRes
	if err := msg.Decode(&request); err != nil {
		log.Error("Received nodes from remote", "msg", msg, "error", err)
		return ErrResp(ErrDecode, "msg %v: %v", msg, err)
	}
	log.Trace("Received bandwidth test msg from remote", "request", request)

	if request.Allowed == 0 {
		log.Error("Remote node do not allowed to bw test.")
		return errors.New("remote node do not allowed to bw test")
	}
	if time.Unix(int64(request.Expir), 0).Before(time.Now()) {
		log.Error("Test bandwidth msg timeout.")
		return errors.New("test bandwidth msg timeout")
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("Test bandwidth panic.", "ip", p.RemoteIP(), "port", p.RemoteIperfPort())
				p.log.Error("Test bandwidth panic.", "r", r)
			}
		}()

		p.log.Debug("Test bandwidth start", "ip", p.RemoteIP(), "port", p.RemoteIperfPort())

		result := prm.startTest(p.RemoteIP(), strconv.Itoa(p.RemoteIperfPort()))
		p.lock.Lock()
		defer p.lock.Unlock()
		p.bandwidth = result
		p.log.Info("Test bandwidth ok", "result", result)
	}()

	return nil
}

func exec_shell(s string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("/bin/bash", "-c", s)

	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}
