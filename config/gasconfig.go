package config


import (
	"math/big"

)

type GasConfig struct {
	Blocks     int
	Percentile int
	Default    *big.Int `toml:",omitempty"`
}