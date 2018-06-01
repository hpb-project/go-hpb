package config


import (
	"math/big"

)

var DefaultGasConfig = GasConfig{
	Blocks:     10,
	Percentile: 50,
}
type GasConfig struct {
	Blocks     int
	Percentile int
	Default    *big.Int `toml:",omitempty"`
}