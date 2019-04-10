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

// Package p2p implements the Hpb p2p network protocols.
package p2p

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"math/rand"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/mclock"
	"github.com/hpb-project/go-hpb/event"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/network/p2p/nat"
	"github.com/hpb-project/go-hpb/network/p2p/netutil"
	"github.com/hpb-project/go-hpb/boe"
	"strings"
	"path/filepath"
	"os"
	"github.com/hpb-project/go-hpb/config"
)

const (
	defaultDialTimeout      = 15 * time.Second

	// Maximum number of concurrently handshaking inbound connections.
	maxAcceptConns = 100

	// Maximum number of concurrently dialing outbound connections.
	maxActiveDialTasks = 4

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")

// Config holds Server options.
type Config struct {
	PrivateKey      *ecdsa.PrivateKey `toml:"-"`
	Name            string `toml:"-"`
	BootstrapNodes  []*discover.Node
	StaticNodes     []*discover.Node
	NetRestrict     *netutil.Netlist `toml:",omitempty"`
	NodeDatabase    string `toml:",omitempty"`
	Protocols       []Protocol `toml:"-"`
	ListenAddr      string
	NAT             nat.Interface `toml:",omitempty"`

	EnableMsgEvents bool
	NetworkId       uint64
	CoinBase        common.Address

	TestMode        bool
}

// Server manages all peer connections.
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	newTransport func(net.Conn) transport
	newPeerHook  func(*PeerBase)

	lock    sync.Mutex // protects running
	running bool

	ntab         discoverTable

	listener     net.Listener
	ourHandshake *protoHandshake
	lastLookup   time.Time

	// These are for Peers, PeerCount (and nothing else).
	peerOp     chan peerOpFunc
	peerOpDone chan struct{}

	quit          chan struct{}
	addstatic     chan *discover.Node
	removestatic  chan *discover.Node
	posthandshake chan *conn
	addpeer       chan *conn
	delpeer       chan peerDrop
	loopWG        sync.WaitGroup // loop, listenLoop

	//peerFeed      event.Feed
	peerEvent    *event.SyncEvent

	localType    discover.NodeType

	dialer        NodeDialer

	delHist       *dialHistory

	//only for test
	//hpflag       bool // block num > 100  this should be false
	synPid       [] SynnodePid

	hdlock       sync.RWMutex
	hdtab        [] HwPair

	setupLock    sync.Mutex

}

type peerOpFunc func(map[discover.NodeID]*PeerBase)

type peerDrop struct {
	*PeerBase
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
)
const RandNonceSize = 32
// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd net.Conn
	transport
	flags connFlag
	cont  chan error      // The run loop uses cont to signal errors to SetupConn.

	id    discover.NodeID // valid after the encryption handshake
	//caps  []Cap           // valid after the protocol handshake
	//name  string          // valid after the protocol handshake


	our   protoHandshake  // valid after the protocol handshake
	their protoHandshake  // valid after the protocol handshake

	isboe bool            // valid after the protocol handshake

	//rport  int            // valid after the protocol handshake
	//raddr  common.Address // valid after the protocol handshake
	//rrand  []byte         // valid after the protocol handshake
}

type transport interface {
	// The two handshakes.
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, []byte, []byte, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	doHardwareTable(our *hardwareTable) (*hardwareTable, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because NsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.id != discover.NodeID{}) {
		s += " " + c.id.String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	return c.flags&f != 0
}

// Peers returns all connected peers.
func (srv *Server) Peers() []*PeerBase {
	var ps []*PeerBase
	select {
	// Note: We'd love to put this function into a variable but
	// that seems to cause a weird compiler error in some
	// environments.
	case srv.peerOp <- func(peers map[discover.NodeID]*PeerBase) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	}:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return ps
}

// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	select {
	case srv.peerOp <- func(ps map[discover.NodeID]*PeerBase) { count = len(ps) }:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return count
}

// AddPeer connects to the given node and maintains the connection until the
// server is shut down. If the connection fails for any reason, the server will
// attempt to reconnect the peer.
func (srv *Server) AddPeer(node *discover.Node) {
	select {
	case srv.addstatic <- node:
	case <-srv.quit:
	}
}

// RemovePeer disconnects from the given node
func (srv *Server) RemovePeer(node *discover.Node) {
	select {
	case srv.removestatic <- node:
	case <-srv.quit:
	}
}

// SubscribePeers subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(et event.EventType) event.Subscriber {
	return srv.peerEvent.Subscribe(et)
}

// Self returns the local node's endpoint information.
func (srv *Server) Self() *discover.Node {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return &discover.Node{IP: net.ParseIP("0.0.0.0")}
	}
	return srv.makeSelf(srv.listener)
}

func (srv *Server) makeSelf(listener net.Listener) *discover.Node {
	// If the server's not running, return an empty node.
	// If the node is running but discovery is off, manually assemble the node infos.
	if srv.ntab == nil {
		// Inbound connections disabled, use zero address.
		if listener == nil {
			return &discover.Node{IP: net.ParseIP("0.0.0.0"), ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
		}
		// Otherwise inject the listener address too
		addr := listener.Addr().(*net.TCPAddr)
		return &discover.Node{
			ID:  discover.PubkeyID(&srv.PrivateKey.PublicKey),
			IP:  addr.IP,
			TCP: uint16(addr.Port),
		}
	}
	// Otherwise return the discovery node.
	return srv.ntab.Self()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if !srv.running {
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.loopWG.Wait()
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	log.Info("Starting P2P networking")
	rand.Seed(time.Now().Unix())

	// static fields
	if srv.PrivateKey == nil {
		return fmt.Errorf("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}

	srv.quit = make(chan struct{})
	srv.addpeer = make(chan *conn)
	srv.delpeer = make(chan peerDrop)
	srv.posthandshake = make(chan *conn)
	srv.addstatic = make(chan *discover.Node)
	srv.removestatic = make(chan *discover.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})
	srv.peerEvent = event.NewEvent()
	srv.delHist = new(dialHistory)

	srv.dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}

	// node table
	ntab, ourend, err := discover.ListenUDP(srv.PrivateKey, srv.localType, srv.ListenAddr, srv.NAT, srv.NodeDatabase, srv.NetRestrict)
	if err != nil {
		return err
	}
	if err := ntab.SetFallbackNodes(srv.BootstrapNodes); err != nil {
		return err
	}
	srv.ntab = ntab

	// handshake
	srv.ourHandshake = &protoHandshake{Version: config.VersionID, Name: srv.Name, ID: discover.PubkeyID(&srv.PrivateKey.PublicKey), End:ourend}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	srv.ourHandshake.Caps = append(srv.ourHandshake.Caps,Cap{config.Version, 0})
	v, err := boe.BoeGetInstance().GetVersion()
	if err == nil{
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps,Cap{v.VersionString(), 0})
	}else {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps,Cap{"N.A", 0})
		log.Error("p2p get boe version","error",err)
	}
	srv.ourHandshake.CoinBase = srv.CoinBase

	if srv.ListenAddr == "" {
		log.Error("P2P server start, listen address is nil")
	}
	if err := srv.startListening(); err != nil {
		return err
	}

	//////////////////////////////////////////////////////////////////////////////////////////////
	if srv.TestMode {
		srv.parseSynnode()
	}
	//////////////////////////////////////////////////////////////////////////////////////////////

	log.Info("Server start with type.","NodeType",srv.localType.ToString())

	dialer := newDialState(srv.StaticNodes, srv.BootstrapNodes, srv.ntab, srv.NetRestrict)
	srv.loopWG.Add(1)
	go srv.run(dialer)
	srv.running = true

	return nil
}

func (srv *Server) startListening() error {
	// Launch the TCP listener.
	listener, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener
	srv.loopWG.Add(1)
	go srv.listenLoop()
	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "hpb p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}

type dialer interface {
	newTasks(running int, peers map[discover.NodeID]*PeerBase, now time.Time) []task
	taskDone(task, time.Time)
	addStatic(*discover.Node)
	removeStatic(*discover.Node)
}

func (srv *Server) run(dialstate dialer) {
	defer srv.loopWG.Done()
	var (
		peers        = make(map[discover.NodeID]*PeerBase)
		taskdone     = make(chan task, maxActiveDialTasks)
		runningTasks []task
		queuedTasks  []task // tasks that can't run yet
	)

	// removes t from runningTasks
	delTask := func(t task) {
		for i := range runningTasks {
			if runningTasks[i] == t {
				runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
				break
			}
		}
	}
	// starts until max number of active tasks is satisfied
	startTasks := func(ts []task) (rest []task) {
		i := 0
		for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
			t := ts[i]
			go func() {
				//log.Error("###### start task.","task",t)
				//time.Sleep(time.Second*time.Duration(rand.Intn(3)))
				t.Do(srv)
				//time.Sleep(time.Second*time.Duration(rand.Intn(3)))
				//log.Error("###### task done.")
				taskdone <- t
				}()
			runningTasks = append(runningTasks, t)
		}
		return ts[i:]
	}
	scheduleTasks := func() {
		// Start from queue first.
		queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
		// Query dialer for new tasks and start as many as possible now.
		if len(runningTasks) < maxActiveDialTasks {
			var nt []task
			if srv.localType == discover.BootNode {
				nt = append(nt, &waitExpireTask{time.Second})
			}else{
				nt = dialstate.newTasks(len(runningTasks)+len(queuedTasks), peers, time.Now())
			}
			queuedTasks = append(queuedTasks, startTasks(nt)...)
		}
	}

running:
	for {
		scheduleTasks()

		srv.delHist.expire(time.Now())
		log.Trace("###### Server running: expire node from history.","DelHist",srv.delHist.Len())
		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case n := <-srv.addstatic:
			// This channel is used by AddPeer to add to the
			// ephemeral static peer list. Add it to the dialer,
			// it will keep the node connected.
			log.Debug("Adding static node", "node", n)
			dialstate.addStatic(n)
		case n := <-srv.removestatic:
			// This channel is used by RemovePeer to send a
			// disconnect request to a peer and begin the
			// stop keeping the node connected
			log.Debug("Removing static node", "node", n)
			dialstate.removeStatic(n)
			if p, ok := peers[n.ID]; ok {
				p.Disconnect(DiscRequested)
			}
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}
		case t := <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			//log.Error("###### Dial task done", "task", t)
			dialstate.taskDone(t, time.Now())
			delTask(t)
		case c := <-srv.posthandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			err := srv.encHandshakeChecks(peers, c)
			if err == DiscAlreadyConnected {
				log.Debug("####discAlreadyConnected", "nid", c.id[0:8])
				nid := c.id
				delete(peers, nid)
				shortid := fmt.Sprintf("%x", nid[0:8])
				if err := PeerMgrInst().unregister(shortid); err != nil {
					log.Debug("Peer removal failed", "peer", shortid, "err", err)
				}
				srv.ntab.RemoveNode(nid)
			}
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case c := <-srv.addpeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.protoHandshakeChecks(peers, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := newPeerBase(c, srv.Protocols[0], srv.ntab)
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = srv.peerEvent
				}

				p.beatStart  = time.Now()
				srv.setPeerInitType(p, c.isboe)
				//////////////////////////////////////////////////////////

				log.Debug("Server add peer base to run.", "id", c.id, "raddr", c.fd.RemoteAddr())
				peers[c.id] = p
				go srv.runPeer(p)
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case pd := <-srv.delpeer:
			// A peer disconnected.
			nid := pd.ID()
			d := common.PrettyDuration(mclock.Now() - pd.created)
			//pd.log.Info("Removing p2p peer", "duration", d)
			pd.log.Info("Removing p2p peer", "id", nid, "duration", d, "type", pd.localType.ToString(), "req", pd.requested, "err", pd.err)
			delete(peers, nid)

			shortid := fmt.Sprintf("%x", nid[0:8])
			if err := PeerMgrInst().unregister(shortid); err != nil {
				log.Debug("Peer removal failed", "peer", shortid, "err", err)
			}

			srv.ntab.RemoveNode(nid)

			expire := time.Second*time.Duration(10+rand.Intn(20))
			srv.delHist.add(nid, time.Now().Add(expire))
			log.Debug("Server running: add node to history.","expire",expire)

		}
	}

	log.Debug("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}

	// Disconnect all peers.
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
		delete(peers, p.ID())
	}
}

func (srv *Server) protoHandshakeChecks(peers map[discover.NodeID]*PeerBase, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.their.Caps) == 0 {
		//log.Error("Protocol Handshake Checks Error")
		return DiscUselessPeer
	}
	// Repeat the encryption handshake checks because the
	// peer set might have changed between the handshakes.
	return srv.encHandshakeChecks(peers, c)
}

func (srv *Server) encHandshakeChecks(peers map[discover.NodeID]*PeerBase, c *conn) error {
	switch {
	case peers[c.id] != nil:
		p := peers[c.id]
		go p.Disconnect(DiscAlreadyConnected)
		return DiscAlreadyConnected
	case c.id == srv.Self().ID:
		return DiscSelf
	default:
		return nil
	}
}

type tempError interface {
	Temporary() bool
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	defer srv.loopWG.Done()
	//log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener))

	// This channel acts as a semaphore limiting
	// active inbound connections that are lingering pre-handshake.
	// If all slots are taken, no further connections are accepted.
	tokens := maxAcceptConns

	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	for {
		// Wait for a handshake slot before accepting.
		<-slots

		var (
			fd  net.Conn
			err error
		)
		for {
			fd, err = srv.listener.Accept()
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				log.Debug("Read error", "err", err)
				return
			}
			break
		}

		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}

		fd = newMeteredConn(fd, true)
		log.Info("Accepted connection", "addr", fd.RemoteAddr())

		// Spawn the handler. It will give the slot back when the connection
		// has been established.
		go func() {
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	if !running {
		c.close(errServerStopped)
		return
	}

	//srv.setupLock.Lock()
	//defer srv.setupLock.Unlock()

	// Run the encryption handshake.
	var err error
	var ourRand, theirRand []byte
	if c.id, ourRand, theirRand, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {
		log.Debug("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "reason", err)
		c.close(err)
		return
	}
	clog := log.New("id", c.id, "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		c.close(DiscUnexpectedIdentity)
		clog.Error("Dialed identity mismatch", "want", c, dialDest.ID)
		return
	}
	if err := srv.checkpoint(c, srv.posthandshake); err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		c.close(err)
		return
	}
	log.Debug("Do enc handshake OK.","id",c.id)

	/////////////////////////////////////////////////////////////////////////////////
	// Run the protocol handshake
	c.our = *srv.ourHandshake
	c.our.RandNonce = ourRand

	if c.our.Sign, err = boe.BoeGetInstance().HW_Auth_Sign(theirRand); err!=nil{
		clog.Debug("Do hardware sign  error.","err",err)
		//todo close and return
	}
	clog.Debug("Hardware has signed remote rand.","rand",theirRand,"sign",c.our.Sign)



	their, err := c.doProtoHandshake(&c.our)
	if err != nil {
		clog.Debug("Failed proto handshake", "err", err)
		c.close(err)
		return
	}
	if their.ID != c.id {
		clog.Error("Wrong devp2p handshake identity", "err", their.ID)
		c.close(DiscUnexpectedIdentity)
		return
	}
	c.their = *their
	clog.Debug("Do protocol handshake OK.","id",c.id)
	clog.Trace("Do protocol handshake.","our",c.our,"their",c.their)

	/////////////////////////////////////////////////////////////////////////////////
	isRemoteBoot := false
	hdtab := srv.getHdtab()

	for _, n := range srv.BootstrapNodes {
		if c.id == n.ID {
			clog.Info("Remote node is boot.","id",c.id)
			c.isboe = true
			isRemoteBoot = true
		}
	}

	if !c.isboe {
		remoteCoinbase := strings.ToLower(c.their.CoinBase.String())
		clog.Trace("Remote coinbase","address",remoteCoinbase)
		if len(hdtab) == 0 {
			clog.Debug("Do not ready for connected.","id",c.id.TerminalString())
			c.close(DiscHwSignError)
			return
		}

		for _,hw := range hdtab {
			if hw.Adr == remoteCoinbase {
				clog.Debug("Input to boe paras","rand",c.our.RandNonce,"hid",hw.Hid,"cid",hw.Cid,"sign",c.their.Sign)
				c.isboe = boe.BoeGetInstance().HW_Auth_Verify(c.our.RandNonce,hw.Hid,hw.Cid,c.their.Sign)
				clog.Info("Boe verify the remote.","id",c.id.TerminalString(),"result",c.isboe)
			}
		}
	}
	clog.Info("Verify the remote hardware.","id",c.id.TerminalString(),"result",c.isboe)


	if !srv.TestMode && srv.localType == discover.SynNode  && c.isboe == false {
		clog.Debug("SynNode peer SynNode, dorp peer.")
		c.close(DiscHwSignError)
		return
	}


	if true || isRemoteBoot || srv.localType == discover.BootNode {

		ourHdtable := &hardwareTable{Version:0x00,Hdtab:hdtab}
		theirHdtable, err := c.doHardwareTable(ourHdtable)
		if err != nil {
			clog.Debug("Failed hardware table handshake", "reason", err)
			c.close(err)
			return
		}

		clog.Trace("Exchange hardware table.","our",ourHdtable, "their",theirHdtable)

		if isRemoteBoot{
			srv.updateHdtab(theirHdtable.Hdtab,true)
			clog.Trace("Update hardware table from boot.","srv hdtab", srv.getHdtab() )
		}
	}

	/////////////////////////////////////////////////////////////////////////////////
	if err := srv.checkpoint(c, srv.addpeer); err != nil {
		clog.Warn("Rejected peer", "err", err, "dialDest",dialDest)
		c.close(err)
		return
	}
}

func  (srv *Server) updateHdtab(pairs [] HwPair, boot bool) error {

	log.Trace("hw pairs from prometheus", "boot", boot, "pairs", pairs)

	if len(srv.hdtab) == len(pairs) {
		theSame := true
		for _,our := range srv.hdtab {
			find := false
			for _, there:= range pairs {
				if our.Adr == there.Adr{
					find = true
					break
				}
			}

			if !find{
				log.Debug("update hardware table do not fond.","address",our.Adr)
				theSame = false
				break
			}
		}

		if theSame {
			log.Debug("do not need update hardware table.")
			return nil
		}
	}

	log.Trace("server need to update hardware table", "boot", boot, "our", len(srv.hdtab), "there", len(pairs), "hdtab", pairs)
	log.Debug("server need to update hardware table", "boot", boot, "our", len(srv.hdtab), "there", len(pairs))
	srv.hdlock.Lock()
	defer srv.hdlock.Unlock()
	srv.hdtab = pairs

	return nil
}

func  (srv *Server) getHdtab() [] HwPair {
	srv.hdlock.RLock()
	defer srv.hdlock.RUnlock()
	return srv.hdtab
}

func  (srv *Server) getHdtabSize() int {
	srv.hdlock.RLock()
	defer srv.hdlock.RUnlock()
	return len(srv.hdtab)
}
// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	}
	select {
	case err := <-c.cont:
		return err
	case <-srv.quit:
		return errServerStopped
	}
}

// runPeer runs in its own goroutine for each peer.
// it waits until the Peer logic returns and removes
// the peer.
func (srv *Server) runPeer(p *PeerBase) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}

	// broadcast peer add
	srv.peerEvent.Notify(PeerEventAdd,&PeerEvent{
		Type: PeerEventAdd,
		Peer: p.ID(),
		})

	// run the protocol
	remoteRequested, err := p.run()

	// broadcast peer drop
	srv.peerEvent.Notify(PeerEventDrop,&PeerEvent{
		Type:  PeerEventDrop,
		Peer:  p.ID(),
		Error: err.Error(),
	})

	// Note: run waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	log.Debug("Server stop to run peer","id",p.ID(),"err",err)
	if err.Error() == DiscAlreadyConnected.Error(){
		p.log.Debug("######DO not stop already connected peer######")
		//return
	}
	srv.delpeer <- peerDrop{p, err, remoteRequested}
}


func (srv *Server) setPeerInitType(p *PeerBase,isboe bool) {

	p.localType = srv.localType
	p.remoteType = discover.SynNode

	for _, n := range srv.BootstrapNodes {
		if n.ID == p.ID() {
			p.remoteType = discover.BootNode
			p.log.Info("P2P set init peer remote type bootnode")
			return
		}
	}

	if isboe {
		p.remoteType = discover.PreNode
		p.log.Info("P2P set init peer remote type prenode")
		return
	}

	if srv.TestMode {
		p.remoteType = discover.PreNode
		for _, spid := range srv.synPid {
			if  spid.PID == p.ID().TerminalString() {
				p.remoteType = discover.SynNode
				p.log.Info("P2P set init peer remote type synnode (TestMode)")
				return
			}
		}
		p.log.Info("P2P set init peer remote type prenode (TestMode)")
	}


}
///////////////////////////////////////////////////////////////////////////////

//for test synnode
const  synnodeFile  = "synnode.json"
type SynnodePid struct {
	PID    string     `json:"pid"`
}

func (srv *Server) parseSynnode()  error{

	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	filename := filepath.Join(dir, synnodeFile)
	log.Debug("Parse syn node pid from config.","filename",filename)


	if err := common.LoadJSON(filename, &srv.synPid); err != nil {
		log.Warn(fmt.Sprintf("Can't load file %s: %v", filename, err))
		return nil
	}
	log.Debug("Parse syn node pid from config.","synPid",srv.synPid)

	return  nil
}

///////////////////////////////////////////////////////////////////////////////
