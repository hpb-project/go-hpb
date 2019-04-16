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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hpb-project/go-hpb/account"
	"github.com/hpb-project/go-hpb/account/keystore"
	"github.com/hpb-project/go-hpb/blockchain"
	"github.com/hpb-project/go-hpb/blockchain/bloombits"
	"github.com/hpb-project/go-hpb/blockchain/storage"
	"github.com/hpb-project/go-hpb/blockchain/types"
	"github.com/hpb-project/go-hpb/common/constant"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/common/rlp"
	"github.com/hpb-project/go-hpb/network/p2p"
	"github.com/hpb-project/go-hpb/network/rpc"
	"github.com/hpb-project/go-hpb/synctrl"
	"github.com/hpb-project/go-hpb/txpool"
	"github.com/prometheus/prometheus/util/flock"
	//"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/boe"
	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/config"
	"github.com/hpb-project/go-hpb/consensus"
	"github.com/hpb-project/go-hpb/consensus/prometheus"
	"github.com/hpb-project/go-hpb/event/sub"
	"github.com/hpb-project/go-hpb/internal/debug"
	"github.com/hpb-project/go-hpb/internal/hpbapi"
	"github.com/hpb-project/go-hpb/node/db"
	"github.com/hpb-project/go-hpb/node/gasprice"
	"github.com/hpb-project/go-hpb/worker"
)

// Node is a container on which services can be registered.
type Node struct {
	//eventmux *event.TypeMux // Event multiplexer used between the services of a stack
	accman      *accounts.Manager
	newBlockMux *sub.TypeMux

	Hpbconfig      *config.HpbConfig
	Hpbpeermanager *p2p.PeerManager
	Hpbrpcmanager  *rpc.RpcManager
	Hpbsyncctr     *synctrl.SynCtrl
	Hpbtxpool      *txpool.TxPool
	Hpbbc          *bc.BlockChain
	//Hpbworker       *Worker
	Hpbboe *boe.BoeHandle
	//HpbDb
	HpbDb hpbdb.Database

	networkId     uint64
	netRPCService *hpbapi.PublicNetAPI

	// The genesis block, which is inserted if the database is empty.
	// If nil, the Hpb main net block is used.
	//Genesis *bc.Genesis `toml:",omitempty"`

	Hpbengine consensus.Engine
	//accountManager  *accounts.Manager
	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *bc.ChainIndexer               // Bloom indexer operating during block imports

	// Channel for shutting down the service
	shutdownChan  chan bool    // Channel for shutting down the hpb
	stopDbUpgrade func() error // stop chain db sequential key upgrade

	//ApiBackend      *HpbApiBackend

	miner     *worker.Miner
	gasPrice  *big.Int
	hpberbase common.Address

	ephemeralKeystore string         // if non-empty, the key directory that will be removed by Stop
	instanceDirLock   flock.Releaser // prevents concurrent use of instance directory

	rpcAPIs       []rpc.API   // List of APIs currently provided by the node
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests

	lock       sync.RWMutex
	ApiBackend *HpbApiBackend

	RpcAPIs []rpc.API // List of APIs currently provided by the node

	stop chan struct{} // Channel to wait for termination notifications

	//1:boe init ok  0: boe init fail
	Boeflag uint8
}

/*
// CreateConsensusEngine creates the required type of consensus engine instance for an Hpb service
func CreateConsensusEngine(conf  *config.HpbConfig,  chainConfig *config.ChainConfig, db hpbdb.Database) consensus.Engine {
	if &chainConfig.Prometheus == nil {
		chainConfig.Prometheus = config.MainnetChainConfig.Prometheus
	}
	return prometheus.New(chainConfig.Prometheus, db)
}
*/
// New creates a hpb node, create all object and start
func New(conf *config.HpbConfig) (*Node, error) {

	var coinbasestring string

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
	if conf.Node.Name == config.DatadirDefaultKeyStore {
		return nil, errors.New(`Config.Name cannot be "` + config.DatadirDefaultKeyStore + `"`)
	}
	if strings.HasSuffix(conf.Node.Name, ".ipc") {
		return nil, errors.New(`Config.Name cannot end in ".ipc"`)
	}

	hpbnode := &Node{
		Hpbconfig:      conf,
		Hpbpeermanager: nil, //peermanager,
		Hpbsyncctr:     nil, //syncctr,
		Hpbtxpool:      nil, //hpbtxpool,
		Hpbbc:          nil, //block,
		//boe

		HpbDb:     nil, //db,
		networkId: conf.Node.NetworkId,

		newBlockMux: nil, //eventmux,
		accman:      nil, //am,
		Hpbengine:   nil,

		gasPrice:      conf.Node.GasPrice,
		hpberbase:     common.Address{},
		bloomRequests: make(chan chan *bloombits.Retrieval),
		bloomIndexer:  nil,
		stop:          make(chan struct{}),
	}
	log.Info("Initialising Hpb node", "network", conf.Node.NetworkId)

	hpbdatabase, _ := db.CreateDB(&conf.Node, "chaindata")
	// Ensure that the AccountManager method works before the node has started.
	// We rely on this in cmd/geth.
	am, _, err := makeAccountManager(&conf.Node)
	if err != nil {
		return nil, err
	}
	hpbnode.accman = am

	hpbnode.Hpbboe = boe.BoeGetInstance()
	err = hpbnode.Hpbboe.Init()
	if err != nil {
		log.Warn("Boe init fail.")
		hpbnode.Boeflag = 0
	} else {
		hpbnode.Boeflag = 1
	}

	//Get coinbase from boe and set it to node.hperbase
	coinbasestring, err = hpbnode.Hpbboe.GetBindAccount()
	if err != nil {
		if wallets := hpbnode.AccountManager().Wallets(); len(wallets) > 0 {
			if account := wallets[0].Accounts(); len(account) > 0 {
				hpbnode.hpberbase = account[0].Address
			}
		}
		log.Warn("Get coinbase from boe fail, and set coinbase with account[0]")

	} else {
		hpbnode.hpberbase = common.HexToAddress(coinbasestring)
		//copy(hpbnode.hpberbase[0:], []byte(coinbasestring))
		log.Info("set coinbase of node", ": ", hpbnode.hpberbase.Hex())
	}

	// Note: any interaction with Config that would create/touch files
	// in the data directory or instance directory is delayed until Start.
	//create all object
	peermanager := p2p.PeerMgrInst()
	hpbnode.Hpbpeermanager = peermanager
	hpbnode.Hpbrpcmanager = rpc.RpcMgrInst()

	hpbnode.HpbDb = hpbdatabase

	hpbnode.newBlockMux = new(sub.TypeMux)

	hpbnode.Hpbbc = bc.InstanceBlockChain()

	peermanager.RegChanStatus(hpbnode.Hpbbc.Status)

	txpool.NewTxPool(conf.TxPool, &conf.BlockChain, hpbnode.Hpbbc)
	hpbtxpool := txpool.GetTxPool()

	hpbnode.Hpbtxpool = hpbtxpool
	hpbnode.ApiBackend = &HpbApiBackend{hpbnode, nil}

	gpoParams := conf.Node.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = conf.Node.GasPrice
	}

	hpbnode.ApiBackend.gpo = gasprice.NewOracle(hpbnode.ApiBackend, gpoParams)
	hpbnode.bloomIndexer = NewBloomIndexer(hpbdatabase, params.BloomBitsBlocks)
	return hpbnode, nil
}
func (hpbnode *Node) WorkerInit(conf *config.HpbConfig) error {
	stored := bc.GetCanonicalHash(hpbnode.HpbDb, 0)
	if stored != (common.Hash{}) {
		if !conf.Node.SkipBcVersionCheck {
			bcVersion := bc.GetBlockChainVersion(hpbnode.HpbDb)
			if bcVersion != bc.BlockChainVersion && bcVersion != 0 {
				return fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run geth upgradedb.\n", bcVersion, bc.BlockChainVersion)
			}
			bc.WriteBlockChainVersion(hpbnode.HpbDb, bc.BlockChainVersion)
		}
		engine := prometheus.InstancePrometheus()
		hpbnode.Hpbengine = engine
		//add consensus engine to blockchain
		_, err := hpbnode.Hpbbc.InitWithEngine(engine)
		if err != nil {
			log.Error("add engine to blockchain error")
			return err
		}
		hpbnode.Hpbsyncctr = synctrl.InstanceSynCtrl()
		hpbnode.newBlockMux = hpbnode.Hpbsyncctr.NewBlockMux()

		hpbnode.miner = worker.New(&conf.BlockChain, hpbnode.NewBlockMux(), hpbnode.Hpbengine, hpbnode.hpberbase)
		hpbnode.bloomIndexer.Start(hpbnode.Hpbbc.CurrentHeader(), hpbnode.Hpbbc.SubscribeChainEvent)

	} else {
		return errors.New(`The genesis block is not inited`)
	}
	return nil
}

type ConsensuscfgF struct {
	HpNodesNum       int      //`json:"HpNodesNum"` 			//hp nodes number
	HpVotingRndScope int      //`json:"HpVotingRndScope"`		//hp voting rand selection scope
	FinalizeRetErrIg bool     //`json:"FinalizeRetErrIg"`	 	//finalize return err ignore
	Time             int      //`json:"Time"`					//gen block interval
	Nodeids          []string //`json:"Nodeids"`				//bootnode`s nodeid only add one
}

func parseConsensusConfigFile(conf *config.HpbConfig) {

	path := conf.Node.DataDir + "/" + conf.Node.FNameConsensusCfg
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			log.Info("parse consensus config file success", "err", err)
		} else {
			log.Warn("parse consensus config file fail", "err", err)
			return
		}
	}

	cfgfile := ConsensuscfgF{}
	//ReadFile函数会读取文件的全部内容，并将结果以[]byte类型返回
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("ioutil.ReadFile fail", "err", err)
		return
	}

	//读取的数据为json格式，需要进行解码
	err = json.Unmarshal(data, &cfgfile)
	if err != nil {
		log.Error("json.Unmarshal fail", "err", err)
		return
	}

	//v,_ := hexutil.DecodeUint64(cfgfile.HpNodesNum)
	consensus.HpbNodenumber = cfgfile.HpNodesNum
	consensus.NumberPrehp = cfgfile.HpVotingRndScope
	consensus.IgnoreRetErr = cfgfile.FinalizeRetErrIg
	conf.Prometheus.Period = uint64(cfgfile.Time)

	config.MainnetBootnodes = config.MainnetBootnodes[:0]
	for _, v := range cfgfile.Nodeids {
		config.MainnetBootnodes = append(config.MainnetBootnodes, v)
	}
}

func (hpbnode *Node) Start(conf *config.HpbConfig) error {

	if conf.Node.FNameConsensusCfg != "" {
		parseConsensusConfigFile(conf)
	}

	if config.GetHpbConfigInstance().Node.TestCodeParam == 1 {
		consensus.SetTestParam()
	}

	log.Info("consensus.HpbNodenumber", "value", consensus.HpbNodenumber)
	log.Info("consensus.NumberPrehp", "value", consensus.NumberPrehp)
	log.Info("consensus.IgnoreRetErr", "value", consensus.IgnoreRetErr)
	log.Info("conf.Prometheus.Period", "value", conf.Prometheus.Period)
	for _, v := range config.MainnetBootnodes {
		log.Info("config.MainnetBootnodes", "value", v)
	}
	log.Info("--------------StageNumberII----------------", "value", consensus.StageNumberII)
	log.Info("--------------StageNumberIII---------------", "value", consensus.StageNumberIII)

	hpbnode.startBloomHandlers()

	err := hpbnode.WorkerInit(conf)
	if err != nil {
		log.Error("Worker init failed", ":", err)
		return err
	}
	if hpbnode.Hpbsyncctr == nil {
		log.Error("syncctrl is nil")
		return errors.New("synctrl is nil")
	}
	hpbnode.Hpbsyncctr.Start()
	retval := hpbnode.Hpbpeermanager.Start(hpbnode.hpberbase)
	if retval != nil {
		log.Error("Start hpbpeermanager error")
		return errors.New(`start peermanager error ".ipc"`)
	}
	hpbnode.Hpbpeermanager.RegStatMining(hpbnode.miner.Mining)

	hpbnode.SetNodeAPI()
	hpbnode.Hpbrpcmanager.Start(hpbnode.RpcAPIs)
	hpbnode.Hpbtxpool.Start()

	return nil

}

func makeAccountManager(conf *config.Nodeconfig) (*accounts.Manager, string, error) {
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

// Stop terminates a running node along with all it's services. In the node was
// not started, an error is returned.
func (n *Node) Stop() error {
	n.lock.Lock()
	defer n.lock.Unlock()

	//stop all modules
	n.Hpbboe.Release()
	n.Hpbsyncctr.Stop()
	n.Hpbtxpool.Stop()
	n.miner.Stop()
	n.Hpbpeermanager.Stop()

	n.Hpbrpcmanager.Stop()
	n.HpbDb.Close()

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

	if keystoreErr != nil {
		return keystoreErr
	}
	return nil
}

// Wait blocks the thread until the node is stopped. If the node is not running
// at the time of invocation, the method immediately returns.
func (n *Node) Wait() {
	n.lock.RLock()

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
	if err := n.Start(config.HpbConfigIns); err != nil {
		return err
	}
	return nil
}

// Attach creates an RPC client attached to an in-process API handler.
func (n *Node) Attach(ipc *rpc.Server) (*rpc.Client, error) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	if ipc == nil {
		return nil, ErrNodeStopped
	}
	n.inprocHandler = ipc
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
/*func (n *Node) Server() *p2p.Server {
	n.lock.RLock()
	defer n.lock.RUnlock()

	return n.server
}*/

// DataDir retrieves the current datadir used by the protocol stack.
// Deprecated: No files should be stored in this directory, use InstanceDir instead.
func (n *Node) DataDir() string {
	return n.Hpbconfig.Node.DataDir
}

// InstanceDir retrieves the instance directory used by the protocol stack.
func (n *Node) InstanceDir() string {
	return n.Hpbconfig.Node.InstanceDir()
}

// AccountManager retrieves the account manager used by the protocol stack.
func (n *Node) AccountManager() *accounts.Manager {
	return n.accman
}

// EventMux retrieves the event multiplexer used by all the network services in
// the current protocol stack.
func (n *Node) NewBlockMux() *sub.TypeMux {
	return n.newBlockMux
}

// ResolvePath returns the absolute path of a resource in the instance directory.
func (n *Node) ResolvePath(x string) string {
	return n.Hpbconfig.Node.ResolvePath(x)
}

// apis returns the collection of RPC descriptors this node offers.
func (n *Node) Nodeapis() []rpc.API {
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

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(config.VersionMajor<<16 | config.VersionMinor<<8 | config.VersionPatch),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > config.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", config.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

func (s *Node) ResetWithGenesisBlock(gb *types.Block) {
	s.Hpbbc.ResetWithGenesisBlock(gb)
}

func (s *Node) Hpberbase() (eb common.Address, err error) {
	s.lock.RLock()
	hpberbase := s.hpberbase
	s.lock.RUnlock()

	if hpberbase != (common.Address{}) {
		return hpberbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			return accounts[0].Address, nil
		}
	}
	return common.Address{}, fmt.Errorf("hpberbase address must be explicitly specified")
}

// set in js console via admin interface or wrapper from cli flags
func (self *Node) SetHpberbase(hpberbase common.Address) {
	self.lock.Lock()
	self.hpberbase = hpberbase
	self.lock.Unlock()

	//to be continue
	//self.worker.SetHpberbase(hpberbase)
}

func (s *Node) StartMining(local bool) error {
	//read coinbase from node
	eb := s.hpberbase

	if promeengine, ok := s.Hpbengine.(*prometheus.Prometheus); ok {
		wallet, err := s.accman.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Hpberbase account unavailable locally", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		promeengine.Authorize(eb, wallet.SignHash)
	} else {
		log.Error("Cannot start mining without prometheus", "err", s.Hpbengine)
	}
	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so noone will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.Hpbsyncctr.AcceptTxs, 1)
	}
	go s.miner.Start(eb)
	return nil
}

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
/*func (s *Node) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}
*/

// get all rpc api from modules
func (n *Node) GetAPI() error {
	return nil
}

func (n *Node) SetNodeAPI() error {
	n.RpcAPIs = n.APIs()
	n.RpcAPIs = append(n.RpcAPIs, n.Nodeapis()...)
	return nil
}
