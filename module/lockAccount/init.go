package lockAccount

import "github.com/hpb-project/go-hpb/blockchain"

var (
	name = "lockAccount"
)

func init() {
	bc.RegisterModules(name, NewLockAccountModule())
}
