package example

import "github.com/hpb-project/go-hpb/blockchain"

var (
	name = "example"
)

func init() {
	bc.RegisterModules(name, NewExampleModule())
}
