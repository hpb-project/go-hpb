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


package config

import (
	"crypto/ecdsa"

	/*
		"github.com/hpb-project/ghpb/account"
		"github.com/hpb-project/ghpb/account/keystore"
		"github.com/hpb-project/ghpb/common"
		"github.com/hpb-project/ghpb/common/crypto"
		"github.com/hpb-project/ghpb/common/log"
		"github.com/hpb-project/ghpb/network/p2p"
		"github.com/hpb-project/ghpb/network/p2p/discover"
		"math/big"
		"time"
		*/

)

const (
	DefaultHTTPHost = "localhost" // Default host interface for the HTTP RPC server
	DefaultHTTPPort = 8545        // Default TCP port for the HTTP RPC server
	DefaultWSHost   = "localhost" // Default host interface for the websocket RPC server
	DefaultWSPort   = 8546        // Default TCP port for the websocket RPC server
)

const (
	// BloomBitsBlocks is the number of blocks a single bloom bit section vector
	// contains.
	BloomBitsBlocks uint64 = 4096
)
var DefaultNetworkConfig = NetworkConfig{
	HTTPPort:    DefaultHTTPPort,
	HTTPModules: []string{"net", "web3"},
	WSPort:      DefaultWSPort,
	WSModules:   []string{"net", "web3"},
	ListenAddr:      ":30303",
	MaxPeers:        50,
	NAT:             nat.Any(),
}

var MainnetBootnodes = []string{
	// Hpb Foundation Go Bootnodes
	"hnode://d9db1338cccee56d310a908fcb77b953d8bcc68e2ea62956b6397e1d6c81ff72fcc4cb7939ddf3f65cf26030d357212c4d0e1daebb7971d1386da26bf1f85e64&1@47.91.73.94:30301",
	"hnode://5c643c86d7cccae0f25916aae34a2ee076634a8123088b34b01390f68e3d71126a5fc16161c24b00d7ca05e38f6e85c556325b6dbe399564556d87aa6f08643e&1@47.75.51.144:30301",
	"hnode://63c43fc19bca6770a602eaca3669e131ac38d07b3e40f119cc094af24eca9a98d3d9ad9ef0981f3878b0334a51b59f36bb1ecf3671a483dd5f6261df549c8aa6&1@47.91.47.79:30301",
	"hnode://af6568c2913a99401fa567182a39f89bad7a0a273d2d7ba5a4ec1d02ad9c790c3be3f17ac92da84c5a9ed604cb7d44482783c85792d587f2bfc42b1dccd3d7e5&1@47.92.26.84:30301",
}

// TestnetBootnodes are the hnode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var TestnetBootnodes = []string{
}
type NetworkConfig struct {
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// HTTPHost is the host interface on which to start the HTTP RPC server. If this
	// field is empty, no HTTP API endpoint will be started.
	HTTPHost string `toml:",omitempty"`

	// HTTPPort is the TCP port number on which to start the HTTP RPC server. The
	// default zero value is/ valid and will pick a port number randomly (useful
	// for ephemeral nodes).
	HTTPPort int `toml:",omitempty"`

	// HTTPCors is the Cross-Origin Resource Sharing header to send to requesting
	// clients. Please be aware that CORS is a browser enforced security, it's fully
	// useless for custom HTTP clients.
	HTTPCors []string `toml:",omitempty"`

	// HTTPModules is a list of API modules to expose via the HTTP RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	HTTPModules []string `toml:",omitempty"`

	// WSHost is the host interface on which to start the websocket RPC server. If
	// this field is empty, no websocket API endpoint will be started.
	WSHost string `toml:",omitempty"`

	// WSPort is the TCP port number on which to start the websocket RPC server. The
	// default zero value is/ valid and will pick a port number randomly (useful for
	// ephemeral nodes).
	WSPort int `toml:",omitempty"`

	// WSOrigins is the list of domain to accept websocket requests from. Please be
	// aware that the server can only act upon the HTTP request the client sends and
	// cannot verify the validity of the request header.
	WSOrigins []string `toml:",omitempty"`

	// WSModules is a list of API modules to expose via the websocket RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	WSModules []string `toml:",omitempty"`

	// WSExposeAll exposes all API modules via the WebSocket RPC interface rather
	// than just the public ones.
	//
	// *WARNING* Only set this if the node is running in a trusted network, exposing
	// private APIs to untrusted users is a major security risk.
	WSExposeAll bool `toml:",omitempty"`
	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`



	// DiscoveryV5 specifies whether the the new topic-discovery based V5 discovery
	// protocol should be started or not.
	//DiscoveryV5 bool `toml:",omitempty"`

	// Listener address for the V5 discovery protocol UDP traffic.
	//DiscoveryV5Addr string `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// RoleType sets the node type of this server.
	// One of hpnode,prenode,access,light.
	RoleType string



	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool
