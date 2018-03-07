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

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Hpbereum network.
var MainnetBootnodes = []string{
	// Hpbereum Foundation Go Bootnodes
	"hnode://d9db1338cccee56d310a908fcb77b953d8bcc68e2ea62956b6397e1d6c81ff72fcc4cb7939ddf3f65cf26030d357212c4d0e1daebb7971d1386da26bf1f85e64&1@47.91.73.94:30301",   //France
	"hnode://eda744640de448de398d9636cc1163e449f79c3401dd5801c2d6b0f7519ad63924b2dd6e236d78ed4d8ae097f446fbc92eeae7796f6d1ae2c320d926822bbdc3&1@47.75.51.144:30301",   //Hongkong
	"hnode://7fa2276faf4df728621601561c8a96e0628bf0398de525761404aedeadcf02ca405b0549fc666e2aa0780820d5615826f1689aeb82c6b09fec026c2e084c619c&1@47.91.47.79:30301",    //Sydney
	"hnode://af6568c2913a99401fa567182a39f89bad7a0a273d2d7ba5a4ec1d02ad9c790c3be3f17ac92da84c5a9ed604cb7d44482783c85792d587f2bfc42b1dccd3d7e5&1@47.92.26.84:30301",    //zhangjiakou
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Ropsten test network.
var TestnetBootnodes = []string{
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{
}
