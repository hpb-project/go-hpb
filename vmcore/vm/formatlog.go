package vm

import (
	"fmt"

	"github.com/hpb-project/go-hpb/common/math"
	"github.com/hpb-project/go-hpb/hvm/evm"
	"github.com/hpb-project/go-hpb/node/tracers_v2/logger"
)

// StructLogRes stores a structured log emitted by the EVM while replaying a
// transaction in debug mode
type StructLogRes struct {
	Pc      uint64            `json:"pc"`
	Op      string            `json:"op"`
	Gas     uint64            `json:"gas"`
	GasCost uint64            `json:"gasCost"`
	Depth   int               `json:"depth"`
	Error   error             `json:"error"`
	Stack   []string          `json:"stack"`
	Memory  []string          `json:"memory"`
	Storage map[string]string `json:"storage"`
}

// FormatLogs formats EVM returned structured logs for json output
func FormatLogs2(logs []logger.StructLog) []StructLogRes {
	formatted := make([]StructLogRes, len(logs))
	for index, trace := range logs {
		formatted[index] = StructLogRes{
			Pc:      trace.Pc,
			Op:      trace.Op.String(),
			Gas:     trace.Gas,
			GasCost: trace.GasCost,
			Depth:   trace.Depth,
			Error:   trace.Err,
		}
		if trace.Stack != nil {
			stack := make([]string, len(trace.Stack))
			for i, stackValue := range trace.Stack {
				stack[i] = stackValue.Hex()
			}
			formatted[index].Stack = stack
		}
		if trace.Memory != nil {
			memory := make([]string, 0, (len(trace.Memory)+31)/32)
			for i := 0; i+32 <= len(trace.Memory); i += 32 {
				memory = append(memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
			}
			formatted[index].Memory = memory
		}
		if trace.Storage != nil {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
			}
			formatted[index].Storage = storage
		}
	}
	return formatted
}

func FormatLogs(structLogs []evm.StructLog) []StructLogRes {
	formattedStructLogs := make([]StructLogRes, len(structLogs))
	for index, trace := range structLogs {
		formattedStructLogs[index] = StructLogRes{
			Pc:      trace.Pc,
			Op:      trace.Op.String(),
			Gas:     trace.Gas,
			GasCost: trace.GasCost,
			Depth:   trace.Depth,
			Error:   trace.Err,
			Stack:   make([]string, len(trace.Stack)),
			Storage: make(map[string]string),
		}

		for i, stackValue := range trace.Stack {
			formattedStructLogs[index].Stack[i] = fmt.Sprintf("%x", math.PaddedBigBytes(stackValue, 32))
		}

		for i := 0; i+32 <= len(trace.Memory); i += 32 {
			formattedStructLogs[index].Memory = append(formattedStructLogs[index].Memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
		}

		for i, storageValue := range trace.Storage {
			formattedStructLogs[index].Storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
		}
	}
	return formattedStructLogs
}
