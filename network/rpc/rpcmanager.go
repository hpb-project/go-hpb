package rpc

import (
	"fmt"
	"net"
	"sync"

	"github.com/hpb-project/go-hpb/common/log"
	"sync/atomic"
	"github.com/hpb-project/go-hpb/config"
)

////////////////////////////////////////////////////////////////////////////
type RpcManager struct {
	rpcmgr *RpcMgr
}


var INSTANCE = atomic.Value{}

func RpcMgrInst() *RpcManager {
	if INSTANCE.Load() == nil {
		pm :=&RpcManager{
			rpcmgr: &RpcMgr{},
		}
		INSTANCE.Store(pm)
	}

	return INSTANCE.Load().(*RpcManager)
}

func (prm *RpcManager)Start(apis []API ) error {

	config :=config.GetHpbConfigInstance()
	// for-test
	log.Debug("Para from config.","IpcEndpoint",config.Network.IpcEndpoint,"HttpEndpoint",config.Network.HttpEndpoint,"WsEndpoint",config.Network.WsEndpoint)

	prm.rpcmgr    = &RpcMgr{
		ipcEndpoint:  config.Network.IpcEndpoint,
		httpEndpoint: config.Network.HttpEndpoint,
		wsEndpoint:   config.Network.WsEndpoint,

		httpCors:     config.Network.HTTPCors,
		httpModules:  config.Network.HTTPModules,

		wsOrigins:    config.Network.WSOrigins,
		wsModules:    config.Network.WSModules,
		wsExposeAll:  config.Network.WSExposeAll,
	}
	prm.rpcmgr.startRPC(apis)


	return nil
}



func (prm *RpcManager)Stop(){
	prm.rpcmgr.stopRPC()
}


func (prm *RpcManager)IpcHandle() * Server {
	return prm.rpcmgr.inprocHandler
}


////////////////////////////////////////////////////////////////////////////
// Node is a container on which services can be registered.
type RpcMgr struct {
	rpcAPIs       []API   // List of APIs currently provided by the node
	inprocHandler *Server // In-process RPC request handler to process the API requests


	ipcListener net.Listener // IPC RPC listener socket to serve API requests
	ipcHandler  *Server  // IPC RPC request handler to process the API requests


	httpWhitelist []string     // HTTP RPC modules to allow through this endpoint
	httpListener  net.Listener // HTTP RPC listener socket to server API requests
	httpHandler   *Server  // HTTP RPC request handler to process the API requests


	wsListener net.Listener // Websocket RPC listener socket to server API requests
	wsHandler  *Server  // Websocket RPC request handler to process the API requests

	lock sync.RWMutex


	ipcEndpoint string       // IPC endpoint to listen at (empty = IPC disabled)
	httpEndpoint  string     // HTTP endpoint (interface + port) to listen at (empty = HTTP disabled)
	wsEndpoint string        // Websocket endpoint (interface + port) to listen at (empty = websocket disabled)

	httpCors    []string
	httpModules []string

	wsOrigins   []string
	wsModules   []string
	wsExposeAll bool


}

// startRPC is a helper method to start all the various RPC endpoint during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
func (n *RpcMgr) startRPC(apis []API) error {
	n.rpcAPIs = apis

	// Start the various API endpoints, terminating all in case of errors
	if err := n.startInProc(apis); err != nil {
		return err
	}
	if err := n.startIPC(apis); err != nil {
		n.stopInProc()
		return err
	}
	if err := n.startHTTP(n.httpEndpoint, apis, n.httpModules, n.httpCors); err != nil {
		n.stopIPC()
		n.stopInProc()
		return err
	}
	if err := n.startWS(n.wsEndpoint, apis, n.wsModules, n.wsOrigins, n.wsExposeAll); err != nil {
		n.stopHTTP()
		n.stopIPC()
		n.stopInProc()
		return err
	}

	// All API endpoints started successfully
	return nil
}
func (n *RpcMgr) stopRPC() {
	n.stopWS()
	n.stopHTTP()
	n.stopIPC()
}


// startInProc initializes an in-process RPC endpoint.
func (n *RpcMgr) startInProc(apis []API) error {
	// Register all the APIs exposed by the services
	handler := NewServer()
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
func (n *RpcMgr) stopInProc() {
	if n.inprocHandler != nil {
		n.inprocHandler.Stop()
		n.inprocHandler = nil
	}
}

// startIPC initializes and starts the IPC RPC endpoint.
func (n *RpcMgr) startIPC(apis []API) error {
	// Short circuit if the IPC endpoint isn't being exposed
	if n.ipcEndpoint == "" {
		return nil
	}
	// Register all the APIs exposed by the services
	handler := NewServer()
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
	if listener, err = CreateIPCListener(n.ipcEndpoint); err != nil {
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
			go handler.ServeCodec(NewJSONCodec(conn), OptionMethodInvocation|OptionSubscriptions)
		}
	}()
	// All listeners booted successfully
	n.ipcListener = listener
	n.ipcHandler = handler

	return nil
}

// stopIPC terminates the IPC RPC endpoint.
func (n *RpcMgr) stopIPC() {
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
func (n *RpcMgr) startHTTP(endpoint string, apis []API, modules []string, cors []string) error {
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
	handler := NewServer()
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
	go NewHTTPServer(cors, handler).Serve(listener)
	log.Info(fmt.Sprintf("HTTP endpoint opened: http://%s", endpoint))

	// All listeners booted successfully
	n.httpEndpoint = endpoint
	n.httpListener = listener
	n.httpHandler = handler

	return nil
}

// stopHTTP terminates the HTTP RPC endpoint.
func (n *RpcMgr) stopHTTP() {
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
func (n *RpcMgr) startWS(endpoint string, apis []API, modules []string, wsOrigins []string, exposeAll bool) error {
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
	handler := NewServer()
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
	go NewWSServer(wsOrigins, handler).Serve(listener)
	log.Info(fmt.Sprintf("WebSocket endpoint opened: ws://%s", listener.Addr()))

	// All listeners booted successfully
	n.wsEndpoint = endpoint
	n.wsListener = listener
	n.wsHandler = handler

	return nil
}

// stopWS terminates the websocket RPC endpoint.
func (n *RpcMgr) stopWS() {
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

