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

package node

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"io/ioutil"
	"math/big"


	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/account/keystore"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/prometheus/prometheus/util/flock"
	"github.com/hpb-project/go-hpb/txpool"
	"github.com/hpb-project/go-hpb/blockchain/bloombits"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/synctrl"
	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/blockchain/event"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/internal/hpbapi"
	"github.com/hpb-project/go-hpb/internal/debug"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/solo"
	"github.com/hpb-project/ghpb/protocol"
	"github.com/hpb-project/go-hpb/worker"
)

// Node is a container on which services can be registered.
type Node struct {
	Hpbconfig       *config.HpbConfig
	Hpbpeermanager  *p2p.PeerManager
	Hpbsyncctr      *synctrl.SynCtrl
	Hpbtxpool 		*txpool.TxPool
	Hpbbc           *bc.BlockChain
	//Hpbworker       *Worker
	Hpbboe			*boe.BoeHandle
	//HpbDb
	chainDb  	    hpbdb.Database

	networkId		uint64
	netRPCService   *hpbapi.PublicNetAPI

	//eventmux *event.TypeMux // Event multiplexer used between the services of a stack
	accman   		*accounts.Manager
	eventMux        *event.TypeMux
	Hpbengine          consensus.Engine
	accountManager  *accounts.Manager
	bloomRequests   chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer    *bc.ChainIndexer             // Bloom indexer operating during block imports

	// Channel for shutting down the service
	shutdownChan  chan bool    // Channel for shutting down the hpb
	stopDbUpgrade func() error // stop chain db sequential key upgrade

	//ApiBackend      *HpbApiBackend

	worker     *worker.Miner
	gasPrice        *big.Int
	hpberbase       common.Address

	ephemeralKeystore string         // if non-empty, the key directory that will be removed by Stop
	instanceDirLock   flock.Releaser // prevents concurrent use of instance directory

	rpcAPIs       []rpc.API   // List of APIs currently provided by the node
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests

	lock sync.RWMutex
	ApiBackend *HpbApiBackend
}


// CreateConsensusEngine creates the required type of consensus engine instance for an Hpb service
func CreateConsensusEngine(conf  *config.HpbConfig,  chainConfig *config.ChainConfig, db hpbdb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if &chainConfig.Prometheus == nil {
		chainConfig.Prometheus = config.MainnetChainConfig.Prometheus
	}
	return solo.New()
}
// New creates a hpb node, create all object and start
func New(conf  *config.HpbConfig) (*Node, error){

	confCopy := *conf
	conf = &confCopy
	if conf.Node.DataDir != "" {
		absdatadir, err := filepath.Abs(conf.Node.DataDir)
		if err != nil {
			return nil, err
		}
		conf.Node.DataDir = absdatadir
	}

	// Ensure that the instance name doesn't cause weird conflicts with
	// other files in the data directory.
	if strings.ContainsAny(conf.Node.Name, `/\`) {
		return nil, errors.New(`Config.Name must not contain '/' or '\'`)
	}
	if conf.Node.Name == config.DatadirDefaultKeyStore{
		return nil, errors.New(`Config.Name cannot be "` + config.DatadirDefaultKeyStore + `"`)
	}
	if strings.HasSuffix(conf.Node.Name, ".ipc") {
		return nil, errors.New(`Config.Name cannot end in ".ipc"`)
	}

	// Ensure that the AccountManager method works before the node has started.
	// We rely on this in cmd/geth.
	am, _, err := makeAccountManager(&conf.Node)
	if err != nil {
		return nil, err
	}
	// Note: any interaction with Config that would create/touch files
	// in the data directory or instance directory is delayed until Start.
	//create all object
	peermanager := p2p.PeerMgrInst()
	hpbtxpool      := txpool.GetTxPool()
	db, err      := CreateDB(&conf.Node, "chaindata")
	eventmux    := new(event.TypeMux)
	chainConfig,  genesisHash, genesisErr := bc.SetupGenesisBlock(db, conf.Node.Genesis)
	engine      := CreateConsensusEngine(conf, chainConfig, db)
	syncctr, err     := synctrl.NewSynCtrl(&conf.BlockChain, synctrl.SyncMode(conf.Node.SyncMode), conf.Node.NetworkId, eventmux, hpbtxpool,engine, db)

	block			:= bc.InstanceBlockChain()
	//Hpbworker       *Worker
	//Hpbboe			*boe.BoeHandle


	hpbnode := &Node{
		Hpbconfig:         conf,
		Hpbpeermanager:    peermanager,
		Hpbsyncctr:		   syncctr,
		Hpbtxpool:		   txpool.GetTxPool(),
		Hpbbc:			   block,
		//boe

		chainDb:		   db,
		networkId:		   conf.Node.NetworkId,

		eventMux:          eventmux,
		accountManager:	   am,
		hpbengine:		   engine,

		gasPrice:       conf.Node.GasPrice,
		hpberbase:      conf.Node.Hpberbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(db, config.BloomBitsBlocks),
	}
	log.Info("Initialising Hpb node", "network", conf.Node.NetworkId)

	if !conf.Node.SkipBcVersionCheck {
		bcVersion := bc.GetBlockChainVersion(db)
		if bcVersion != bc.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run geth upgradedb.\n", bcVersion, bc.BlockChainVersion)
		}
		bc.WriteBlockChainVersion(db, bc.BlockChainVersion)
	}
	hpbnode.Hpbbc, err = bc.NewBlockChain(db, &hpbnode.Hpbconfig.BlockChain, hpbnode.hpbengine)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*config.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		hpbnode.Hpbbc.SetHead(compat.RewindTo)
		bc.WriteChainConfig(db, genesisHash, chainConfig)
	}
	hpbnode.bloomIndexer.Start(hpbnode.Hpbbc.CurrentHeader(), hpbnode.Hpbbc.SubscribeChainEvent)


	hpbnode.Hpbtxpool = txpool.NewTxPool(conf.TxPool, &conf.BlockChain, hpbnode.Hpbbc)


	hpbnode.worker = worker.New(&conf.BlockChain, hpbnode.EventMux(), hpbnode.hpbengine)
	//hpbnode.worker.SetExtra(makeExtraData(config.ExtraData))
/*
	hpb.ApiBackend = &HpbApiBackend{hpb, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.GasPrice
	}
	hpbnode.ApiBackend.gpo = gasprice.NewOracle(hpb.ApiBackend, gpoParams)*/

	return hpbnode, nil
}

func (hpnode *Node)Start(conf  *config.HpbConfig) (error){

	retval := hpnode.Hpbpeermanager.Start(conf.Network)
	if retval != nil{
		log.Error("Start hpbpeermanager error")
		return errors.New(`start peermanager error ".ipc"`)
	}
	hpnode.Hpbsyncctr.Start()
	return nil

}



func makeAccountManager(conf  *config.Nodeconfig) (*accounts.Manager, string, error) {
	scryptN := keystore.StandardScryptN
	scryptP := keystore.StandardScryptP
	if conf.UseLightweightKDF {
		scryptN = keystore.LightScryptN
		scryptP = keystore.LightScryptP
	}

	var (
		keydir    string
		ephemeral string
		err       error
	)
	switch {
	case filepath.IsAbs(conf.KeyStoreDir):
		keydir = conf.KeyStoreDir
	case conf.DataDir != "":
		if conf.KeyStoreDir == "" {
			keydir = filepath.Join(conf.DataDir, config.DatadirDefaultKeyStore)
		} else {
			keydir, err = filepath.Abs(conf.KeyStoreDir)
		}
	case conf.KeyStoreDir != "":
		keydir, err = filepath.Abs(conf.KeyStoreDir)
	default:
		// There is no datadir.
		keydir, err = ioutil.TempDir("", "ghpb-keystore")
		ephemeral = keydir
	}
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(keydir, 0700); err != nil {
		return nil, "", err
	}

	return accounts.NewManager(keystore.NewKeyStore(keydir, scryptN, scryptP)), ephemeral, nil
}




func (n *Node) openDataDir() error {
	if n.Hpbconfig.Node.DataDir == "" {
		return nil // ephemeral
	}

	instdir := filepath.Join(n.Hpbconfig.Node.DataDir, n.Hpbconfig.Node.StringName())
	if err := os.MkdirAll(instdir, 0700); err != nil {
		return err
	}
	// Lock the instance directory to prevent concurrent use by another instance as well as
	// accidental use of the instance directory as a database.
	release, _, err := flock.New(filepath.Join(instdir, "LOCK"))
	if err != nil {
		return convertFileLockError(err)
	}
	n.instanceDirLock = release
	return nil
}

// startRPC is a helper method to start all the various RPC endpoint during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
func (n *Node) startRPC(services map[reflect.Type]Service) error {
	// Gather all the possible APIs to surface
	apis := n.apis()
	for _, service := range services {
		apis = append(apis, service.APIs()...)
	}
	// Start the various API endpoints, terminating all in case of errors
	if err := n.startInProc(apis); err != nil {
		return err
	}
	if err := n.startIPC(apis); err != nil {
		n.stopInProc()
		return err
	}
	if err := n.startHTTP(n.httpEndpoint, apis, n.config.HTTPModules, n.config.HTTPCors); err != nil {
		n.stopIPC()
		n.stopInProc()
		return err
	}
	if err := n.startWS(n.wsEndpoint, apis, n.config.WSModules, n.config.WSOrigins, n.config.WSExposeAll); err != nil {
		n.stopHTTP()
		n.stopIPC()
		n.stopInProc()
		return err
	}
	// All API endpoints started successfully
	n.rpcAPIs = apis
	return nil
}

// startInProc initializes an in-process RPC endpoint.
func (n *Node) startInProc(apis []rpc.API) error {
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
		log.Debug(fmt.Sprintf("InProc registered %T under '%s'", api.Service, api.Namespace))
	}
	n.inprocHandler = handler
	return nil
}

// stopInProc terminates the in-process RPC endpoint.
func (n *Node) stopInProc() {
	if n.inprocHandler != nil {
		n.inprocHandler.Stop()
		n.inprocHandler = nil
	}
}

// startIPC initializes and starts the IPC RPC endpoint.
func (n *Node) startIPC(apis []rpc.API) error {
	// Short circuit if the IPC endpoint isn't being exposed
	if n.ipcEndpoint == "" {
		return nil
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
		log.Debug(fmt.Sprintf("IPC registered %T under '%s'", api.Service, api.Namespace))
	}
	// All APIs registered, start the IPC listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = rpc.CreateIPCListener(n.ipcEndpoint); err != nil {
		return err
	}
	go func() {
		log.Info(fmt.Sprintf("IPC endpoint opened: %s", n.ipcEndpoint))

		for {
			conn, err := listener.Accept()
			if err != nil {
				// Terminate if the listener was closed
				n.lock.RLock()
				closed := n.ipcListener == nil
				n.lock.RUnlock()
				if closed {
					return
				}
				// Not closed, just some error; report and continue
				log.Error(fmt.Sprintf("IPC accept failed: %v", err))
				continue
			}
			go handler.ServeCodec(rpc.NewJSONCodec(conn), rpc.OptionMethodInvocation|rpc.OptionSubscriptions)
		}
	}()
	// All listeners booted successfully
	n.ipcListener = listener
	n.ipcHandler = handler

	return nil
}

// stopIPC terminates the IPC RPC endpoint.
func (n *Node) stopIPC() {
	if n.ipcListener != nil {
		n.ipcListener.Close()
		n.ipcListener = nil

		log.Info(fmt.Sprintf("IPC endpoint closed: %s", n.ipcEndpoint))
	}
	if n.ipcHandler != nil {
		n.ipcHandler.Stop()
		n.ipcHandler = nil
	}
}

// startHTTP initializes and starts the HTTP RPC endpoint.
func (n *Node) startHTTP(endpoint string, apis []rpc.API, modules []string, cors []string) error {
	// Short circuit if the HTTP endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
			log.Debug(fmt.Sprintf("HTTP registered %T under '%s'", api.Service, api.Namespace))
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return err
	}
	go rpc.NewHTTPServer(cors, handler).Serve(listener)
	log.Info(fmt.Sprintf("HTTP endpoint opened: http://%s", endpoint))

	// All listeners booted successfully
	n.httpEndpoint = endpoint
	n.httpListener = listener
	n.httpHandler = handler

	return nil
}

// stopHTTP terminates the HTTP RPC endpoint.
func (n *Node) stopHTTP() {
	if n.httpListener != nil {
		n.httpListener.Close()
		n.httpListener = nil

		log.Info(fmt.Sprintf("HTTP endpoint closed: http://%s", n.httpEndpoint))
	}
	if n.httpHandler != nil {
		n.httpHandler.Stop()
		n.httpHandler = nil
	}
}

// startWS initializes and starts the websocket RPC endpoint.
func (n *Node) startWS(endpoint string, apis []rpc.API, modules []string, wsOrigins []string, exposeAll bool) error {
	// Short circuit if the WS endpoint isn't being exposed
	if endpoint == "" {
		return nil
	}
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {
		whitelist[module] = true
	}
	// Register all the APIs exposed by the services
	handler := rpc.NewServer()
	for _, api := range apis {
		if exposeAll || whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
			log.Debug(fmt.Sprintf("WebSocket registered %T under '%s'", api.Service, api.Namespace))
		}
	}
	// All APIs registered, start the HTTP listener
	var (
		listener net.Listener
		err      error
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return err
	}
	go rpc.NewWSServer(wsOrigins, handler).Serve(listener)
	log.Info(fmt.Sprintf("WebSocket endpoint opened: ws://%s", listener.Addr()))

	// All listeners booted successfully
	n.wsEndpoint = endpoint
	n.wsListener = listener
	n.wsHandler = handler

	return nil
}

// stopWS terminates the websocket RPC endpoint.
func (n *Node) stopWS() {
	if n.wsListener != nil {
		n.wsListener.Close()
		n.wsListener = nil

		log.Info(fmt.Sprintf("WebSocket endpoint closed: ws://%s", n.wsEndpoint))
	}
	if n.wsHandler != nil {
		n.wsHandler.Stop()
		n.wsHandler = nil
	}
}

// Stop terminates a running node along with all it's services. In the node was
// not started, an error is returned.
func (n *Node) Stop() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	// Short circuit if the node's not running
	if n.server == nil {
		return ErrNodeStopped
	}

	// Terminate the API, services and the p2p server.
	n.stopWS()
	n.stopHTTP()
	n.stopIPC()
	n.rpcAPIs = nil
	failure := &StopError{
		Services: make(map[reflect.Type]error),
	}
	for kind, service := range n.services {
		if err := service.Stop(); err != nil {
			failure.Services[kind] = err
		}
	}
	n.server.Stop()
	n.services = nil
	n.server = nil

	// Release instance directory lock.
	if n.instanceDirLock != nil {
		if err := n.instanceDirLock.Release(); err != nil {
			log.Error("Can't release datadir lock", "err", err)
		}
		n.instanceDirLock = nil
	}

	// unblock n.Wait
	close(n.stop)

	// Remove the keystore if it was created ephemerally.
	var keystoreErr error
	if n.ephemeralKeystore != "" {
		keystoreErr = os.RemoveAll(n.ephemeralKeystore)
	}

	if len(failure.Services) > 0 {
		return failure
	}
	if keystoreErr != nil {
		return keystoreErr
	}
	return nil
}

// Wait blocks the thread until the node is stopped. If the node is not running
// at the time of invocation, the method immediately returns.
func (n *Node) Wait() {
	n.lock.RLock()
	if n.server == nil {
		n.lock.RUnlock()
		return
	}
	stop := n.stop
	n.lock.RUnlock()

	<-stop
}

// Restart terminates a running node and boots up a new one in its place. If the
// node isn't running, an error is returned.
func (n *Node) Restart() error {
	if err := n.Stop(); err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		return err
	}
	return nil
}

// Attach creates an RPC client attached to an in-process API handler.
func (n *Node) Attach() (*rpc.Client, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	if n.server == nil {
		return nil, ErrNodeStopped
	}
	return rpc.DialInProc(n.inprocHandler), nil
}

// RPCHandler returns the in-process RPC request handler.
func (n *Node) RPCHandler() (*rpc.Server, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	if n.inprocHandler == nil {
		return nil, ErrNodeStopped
	}
	return n.inprocHandler, nil
}

// Server retrieves the currently running P2P network layer. This method is meant
// only to inspect fields of the currently running server, life cycle management
// should be left to this Node entity.
func (n *Node) Server() *p2p.Server {
	n.lock.RLock()
	defer n.lock.RUnlock()

	return n.server
}

// Service retrieves a currently running service registered of a specific type.
func (n *Node) Service(service interface{}) error {
	n.lock.RLock()
	defer n.lock.RUnlock()

	// Short circuit if the node's not running
	if n.server == nil {
		return ErrNodeStopped
	}
	// Otherwise try to find the service to return
	element := reflect.ValueOf(service).Elem()
	if running, ok := n.services[element.Type()]; ok {
		element.Set(reflect.ValueOf(running))
		return nil
	}
	return ErrServiceUnknown
}

// DataDir retrieves the current datadir used by the protocol stack.
// Deprecated: No files should be stored in this directory, use InstanceDir instead.
func (n *Node) DataDir() string {
	return n.config.DataDir
}

// InstanceDir retrieves the instance directory used by the protocol stack.
func (n *Node) InstanceDir() string {
	return n.config.instanceDir()
}

// AccountManager retrieves the account manager used by the protocol stack.
func (n *Node) AccountManager() *accounts.Manager {
	return n.accman
}

// IPCEndpoint retrieves the current IPC endpoint used by the protocol stack.
func (n *Node) IPCEndpoint() string {
	return n.ipcEndpoint
}

// HTTPEndpoint retrieves the current HTTP endpoint used by the protocol stack.
func (n *Node) HTTPEndpoint() string {
	return n.httpEndpoint
}

// WSEndpoint retrieves the current WS endpoint used by the protocol stack.
func (n *Node) WSEndpoint() string {
	return n.wsEndpoint
}

// EventMux retrieves the event multiplexer used by all the network services in
// the current protocol stack.
func (n *Node) EventMux() *event.TypeMux {
	return n.eventmux
}


// OpenDatabase opens an existing database with the given name (or creates one
// if no previous can be found) from within the node's data directory. If the
// node is an ephemeral one, a memory database is returned.
func  OpenDatabase(name string, cache int, handles int) (hpbdb.Database, error) {
	if n.Hpbconfig.Node.DataDir == ""{
		return hpbdb.NewMemDatabase()
	}
	db, err := hpbdb.NewLDBDatabase(n.Hpbconfig.Node.ResolvePath(name), cache, handles)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// CreateDB creates the chain database.
func CreateDB(config *config.Nodeconfig, name string) (hpbdb.Database, error) {
	db, err := OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*hpbdb.LDBDatabase); ok {
		db.Meter("hpb/db/chaindata/")
	}
	return db, nil
}

// ResolvePath returns the absolute path of a resource in the instance directory.
func (n *Node) ResolvePath(x string) string {
	return n.config.resolvePath(x)
}

// apis returns the collection of RPC descriptors this node offers.
func (n *Node) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(n),
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPublicAdminAPI(n),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   debug.Handler,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(n),
			Public:    true,
		}, {
			Namespace: "web3",
			Version:   "1.0",
			Service:   NewPublicWeb3API(n),
			Public:    true,
		},
	}
}
