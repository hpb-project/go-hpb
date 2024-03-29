// Copyright 2018 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2014 The go-ethereum Authors.
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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hpb-project/go-hpb/network/p2p/discover"
	"github.com/hpb-project/go-hpb/network/p2p/nat"
	"github.com/hpb-project/go-hpb/network/p2p/netutil"
)

const (
	DefaultHTTPHost = "localhost" // Default host interface for the HTTP RPC server
	DefaultHTTPPort = 8545        // Default TCP port for the HTTP RPC server
	DefaultWSHost   = "localhost" // Default host interface for the websocket RPC server
	DefaultWSPort   = 8546        // Default TCP port for the websocket RPC server
)

const (
	clientIdentifier = "ghpb" // Client identifier to advertise over the network
)
const (
	// BloomBitsBlocks is the number of blocks a single bloom bit section vector
	// contains.
	BloomBitsBlocks uint64 = 4096
)

var DefaultNTConfig = NetworkConfig{

	HTTPPort:         DefaultHTTPPort,
	HTTPModules:      []string{"net", "web3", "prometheus"},
	WSPort:           DefaultWSPort,
	WSModules:        []string{"net", "web3", "prometheus"},
	HTTPVirtualHosts: []string{"localhost"},
	HTTPTimeouts:     DefaultHTTPTimeouts,
	ListenAddr:       ":30303",
	MaxPeers:         50,
	NAT:              nat.Any(),
	IpcEndpoint:      DefaultIPCEndpoint(clientIdentifier),
	HttpEndpoint:     DefaultHTTPEndpoint(),
	WsEndpoint:       DefaultWSEndpoint(),
}

//var MainnetBootnodes_v1 = []string{ // old version used.
//	"hnode://73c8ac9dddc8f094d28f42e1ec5c3e8000cad25be152c147fceacc27953d58e64bfe9f555145d93f9f6b995bab984411941751fef3bd460f74c0151eb0432b56@bootnode1.hpb.io:30303",
//	"hnode://1c129009d0e9c56e79b6f4157497d8ac2810ea83fc1f6ed4b6244406597d821f52bb0d210157854d861d2f6099fa948bc5a03d2f4f1bcae70dc6e9c535e586f9@bootnode2.hpb.io:30303",
//	"hnode://f3282847f29cfea1dd741246cc17b9a0dcdd8b0b9dfce2a985d2358497458135e81942ae7155cfd2fe23e1da30f18fc1fa2c56d3675aba51e7c67f83681fded5@bootnode3.hpb.io:30303",
//	"hnode://dd2fd6ea314041c0e20aed4ee4159ab172a4ddb944459d147bdb28461937841ee069c44fe0915be9f74d929562968fb9720362937a898e2ec3a598fa3fe1f33b@bootnode4.hpb.io:30303",
//	"hnode://a6ef92a46adb69f94f2d48ff20f7800fb057d6aba7945e5af062ef27be5598072c5ce083ec5a2c89f80d112401c261b9ba9dacbd53aeb7c8243685d537edadb9@bootnode5.hpb.io:30303",
//}

var MainnetBootnodes_v3 = []string{ // old version used.
	"hnode://0a4ee79961f00dcf3601ae662cf010760c8166a22eac5bfddf28ab16513b497f72a1d6ebc6eb7afdfec391fa2b8997b4a74b33e7f3af5c81205f5ebb167658df@bootnode1.hpb.io:30306",
	"hnode://f31f58a70cd4880f506c8f1038be2c48823bb6f43529b16e82d67f5d74ff3c02e339f6b9ccb61c69c32f798ace3d8c8ac49014e9fefb58d9774c60e6f80c512e@bootnode2.hpb.io:30306",
	"hnode://230af50ef9f6209129be4879e5e0ce53fdce2de1b48a18388bfb15009998a4985eb864459c3c013f999d1ba44748b10a746e20e02da159f10b104025cb7f932a@bootnode3.hpb.io:30306",
	"hnode://283d1de984ee071e322a96e3a2e98cfba1adb4dee23e4af5846f72e23b364c11ab5280d1a8511394e03cb4dc6b3b6d86cf862d87afcbd2f324deb220390bbbae@bootnode4.hpb.io:30306",
	"hnode://33c5b55d6dc4aaf6bcb4502d69bf4ca8db7550e7b01cae1c53fca9ce8b60b440102d4c4dcd578136d64c8934fc90f0ad96bcf828bc611a9bbb7ea33369bc1aa0@bootnode5.hpb.io:30306",
}

//var MainnetBootnodes_v2 = []string{ // old version used.
//	"hnode://fdfbe84bf5e2836bcca2ec10462f9e94008b89823a3114aa759a709622532a7d16390456adb05efd6d2f7e6760571eed128cee4a052cdbb621031a61db8f0f37@bootnode1.hpb.io:30305",
//	"hnode://a7d22e7e23f2d66d84bf3a02e8e085ea003329ef7cd76df851c0d62ecf9c5492411d46d979ce0ca2fc17264fe30acc53051970952178993a9627a7064e7530ff@bootnode2.hpb.io:30305",
//	"hnode://71ec147e30eec314aaf6d388e1d0a62abc525b585534211dcc19d2d0bd3a168208c346761b6abdc06f7e18264b22626a5e418fff64ddbd6d1887e09c25733376@bootnode3.hpb.io:30305",
//	"hnode://a6aef2f8460ff328c748a9a519c9a1d9a0096e61beb47c6389425155cc018233058f45d6ce994f0ca8f328cc8ea5e8cef8920373e9dd5544cc1589a0be7634d3@bootnode4.hpb.io:30305",
//	"hnode://c5133467ea929c7d71f349bfb6dee1ab23ad3c05e95178e3711d1f64b6d9cd82a2a65f177de3ef175f532573d194048fed8d2c9a5602a7ab9ef05c672eb17db0@bootnode5.hpb.io:30305",
//}

var MainnetBootnodes = []string{ // new version used.
	"hnode://924548a360bf36833bbf202ea79c66268cda2e12250e94fa2d98a1f7ab2c7d29b3e13f4817d02863323537a12f544231428faec6a64df016384422bb1f96fe7c@bootnode1.hpb.io:30308",
	"hnode://7326ebe616bfe48440b877162dbd19a9689daaacf3d4ff1b9861c3a72657991b58a178cad45a3e632fc32dbe87193bbde6956f0329190f2838236fae0952e687@bootnode2.hpb.io:30308",
	"hnode://0e7c6af2fe5d0a13bf77ada5477b8ac38b0a48be13ce41c72facd20ce08a364070619d515c5d8dca8b346f49be1680408d95fd53b627f8366e0c68bae0f60ee2@bootnode3.hpb.io:30308",
	"hnode://4178ca45f32609cea1f1e75e8b2e57176d951905b5a7e2324026c2f28042d71b0f9bbf830935431326c55180921b587cdb1f686531f2076c0b509ed6ee9a2602@bootnode4.hpb.io:30308",
	"hnode://6c4ac5224a89c24abceb54203f651adfdf77be53c07094cebc9330063bee4a888177054db3055cdd1e7394d5554b7be48eb14d67df7c6f4902c3cd88e02bdd7c@bootnode5.hpb.io:30308",
}

// TestnetBootnodes are the hnode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var TestnetBootnodes = []string{}

type NetworkConfig struct {
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

	// HTTPVirtualHosts is the list of virtual hostnames which are allowed on incoming requests.
	// This is by default {'localhost'}. Using this prevents attacks like
	// DNS rebinding, which bypasses SOP by simply masquerading as being within the same
	// origin. These attacks do not utilize CORS, since they are not cross-domain.
	// By explicitly checking the Host-header, the server will not allow requests
	// made against the server with a malicious host domain.
	// Requests using ip address directly are not affected
	HTTPVirtualHosts []string `toml:",omitempty"`

	// HTTPModules is a list of API modules to expose via the HTTP RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	HTTPModules []string `toml:",omitempty"`

	// HTTPTimeouts allows for customization of the timeout values used by the HTTP RPC
	// interface.
	HTTPTimeouts HTTPTimeouts

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
	NoDiscovery bool
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

	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	IpcEndpoint     string // IPC endpoint to listen at (empty = IPC disabled)
	HttpEndpoint    string // HTTP endpoint (interface + port) to listen at (empty = HTTP disabled)
	WsEndpoint      string // Websocket endpoint (interface + port) to listen at (empty = websocket disabled)
	GraphQLEndPoint string

	BootstrapNodes []*discover.Node
}

// HTTPTimeouts represents the configuration params for the HTTP RPC server.
type HTTPTimeouts struct {
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, ReadHeaderTimeout is used.
	IdleTimeout time.Duration
}

// DefaultHTTPTimeouts represents the default timeout values used if further
// configuration is not provided.
var DefaultHTTPTimeouts = HTTPTimeouts{
	ReadTimeout:  60 * time.Second,
	WriteTimeout: 60 * time.Second,
	IdleTimeout:  600 * time.Second,
}

func DefaultNetworkConfig() NetworkConfig {
	cfg := DefaultNTConfig

	cfg.HTTPModules = append(cfg.HTTPModules, "hpb")
	cfg.WSModules = append(cfg.WSModules, "hpb")

	cfg.HTTPVirtualHosts = append(cfg.HTTPVirtualHosts, "localhost")
	cfg.HTTPTimeouts = DefaultHTTPTimeouts

	return cfg
}

// HTTPEndpoint resolves an HTTP endpoint based on the configured host interface
// and port parameters.
func (c *NetworkConfig) HTTPEndpoint() string {
	if c.HTTPHost == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.HTTPHost, c.HTTPPort)
}

func (c *NetworkConfig) GraphQLEndpoint() string {
	if c.HTTPHost == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.HTTPHost, c.HTTPPort+2)
}

// DefaultHTTPEndpoint returns the HTTP endpoint used by default.
func DefaultHTTPEndpoint() string {
	config := &NetworkConfig{HTTPHost: DefaultHTTPHost, HTTPPort: DefaultHTTPPort}
	return config.HTTPEndpoint()
}

// DefaultIPCEndpoint returns the IPC path used by default.
func DefaultIPCEndpoint(clientIdentifier string) string {
	if clientIdentifier == "" {
		clientIdentifier = strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
		if clientIdentifier == "" {
			panic("empty executable name")
		}
	}
	config := &Nodeconfig{DataDir: DefaultDataDir(), IPCPath: clientIdentifier + ".ipc"}
	return config.IPCEndpoint()
}

// WSEndpoint resolves an websocket endpoint based on the configured host interface
// and port parameters.
func (c *NetworkConfig) WSEndpoint() string {
	if c.WSHost == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.WSHost, c.WSPort)
}

// DefaultWSEndpoint returns the websocket endpoint used by default.
func DefaultWSEndpoint() string {
	config := &NetworkConfig{WSHost: DefaultWSHost, WSPort: DefaultWSPort}
	return config.WSEndpoint()
}
