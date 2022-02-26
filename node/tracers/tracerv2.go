// Copyright 2020 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2018 The go-ethereum Authors.
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

package tracers

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/hpb-project/go-hpb/vmcore"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/crypto"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/hpb-project/go-hpb/evm/vm"
	duktape "gopkg.in/olebedev/go-duktape.v3"
)

// opWrapper provides a JavaScript wrapper around OpCode.
type opWrapper2 struct {
	op vm.OpCode
}

// pushObject assembles a JSVM object wrapping a swappable opcode and pushes it
// onto the VM stack.
func (ow *opWrapper2) pushObject(dc *duktape.Context) {
	obj := dc.PushObject()

	dc.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushInt(int(ow.op)); return 1 })
	dc.PutPropString(obj, "toNumber")

	dc.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushString(ow.op.String()); return 1 })
	dc.PutPropString(obj, "toString")

	dc.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushBoolean(ow.op.IsPush()); return 1 })
	dc.PutPropString(obj, "isPush")
}

// memoryWrapper provides a JavaScript wrapper around vm.Memory.
type memoryWrapper2 struct {
	memory *vm.Memory
}

// slice returns the requested range of memory as a byte slice.
func (mw *memoryWrapper2) slice(begin, end int64) []byte {
	if end == begin {
		return []byte{}
	}
	if end < begin || begin < 0 {
		// TODO(karalabe): We can't js-throw from Go inside duktape inside Go. The Go
		// runtime goes belly up https://github.com/golang/go/issues/15639.
		log.Warn("Tracer accessed out of bound memory", "offset", begin, "end", end)
		return nil
	}
	if mw.memory.Len() < int(end) {
		// TODO(karalabe): We can't js-throw from Go inside duktape inside Go. The Go
		// runtime goes belly up https://github.com/golang/go/issues/15639.
		log.Warn("Tracer accessed out of bound memory", "available", mw.memory.Len(), "offset", begin, "size", end-begin)
		return nil
	}
	return mw.memory.GetCopy(begin, end-begin)
}

// getUint returns the 32 bytes at the specified address interpreted as a uint.
func (mw *memoryWrapper2) getUint(addr int64) *big.Int {
	if mw.memory.Len() < int(addr)+32 || addr < 0 {
		// TODO(karalabe): We can't js-throw from Go inside duktape inside Go. The Go
		// runtime goes belly up https://github.com/golang/go/issues/15639.
		log.Warn("Tracer accessed out of bound memory", "available", mw.memory.Len(), "offset", addr, "size", 32)
		return new(big.Int)
	}
	return new(big.Int).SetBytes(mw.memory.GetPtr(addr, 32))
}

// pushObject assembles a JSVM object wrapping a swappable memory and pushes it
// onto the VM stack.
func (mw *memoryWrapper2) pushObject(dc *duktape.Context) {
	obj := dc.PushObject()

	// Generate the `slice` method which takes two ints and returns a buffer
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		blob := mw.slice(int64(ctx.GetInt(-2)), int64(ctx.GetInt(-1)))
		ctx.Pop2()

		ptr := ctx.PushFixedBuffer(len(blob))
		copy(makeSlice(ptr, uint(len(blob))), blob)
		return 1
	})
	dc.PutPropString(obj, "slice")

	// Generate the `getUint` method which takes an int and returns a bigint
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		offset := int64(ctx.GetInt(-1))
		ctx.Pop()

		pushBigInt(mw.getUint(offset), ctx)
		return 1
	})
	dc.PutPropString(obj, "getUint")
}

// stackWrapper provides a JavaScript wrapper around vm.Stack.
type stackWrapper2 struct {
	stack *vm.Stack
}

// peek returns the nth-from-the-top element of the stack.
func (sw *stackWrapper2) peek(idx int) *big.Int {
	if len(sw.stack.Data()) <= idx || idx < 0 {
		// TODO(karalabe): We can't js-throw from Go inside duktape inside Go. The Go
		// runtime goes belly up https://github.com/golang/go/issues/15639.
		log.Warn("Tracer accessed out of bound stack", "size", len(sw.stack.Data()), "index", idx)
		return new(big.Int)
	}
	return sw.stack.Back(idx).ToBig()
}

// pushObject assembles a JSVM object wrapping a swappable stack and pushes it
// onto the VM stack.
func (sw *stackWrapper2) pushObject(dc *duktape.Context) {
	obj := dc.PushObject()

	dc.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushInt(len(sw.stack.Data())); return 1 })
	dc.PutPropString(obj, "length")

	// Generate the `peek` method which takes an int and returns a bigint
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		offset := ctx.GetInt(-1)
		ctx.Pop()

		pushBigInt(sw.peek(offset), ctx)
		return 1
	})
	dc.PutPropString(obj, "peek")
}

// dbWrapper provides a JavaScript wrapper around vm.Database.
type dbWrapper2 struct {
	db vmcore.StateDB
}

// pushObject assembles a JSVM object wrapping a swappable database and pushes it
// onto the VM stack.
func (dw *dbWrapper2) pushObject(dc *duktape.Context) {
	obj := dc.PushObject()

	// Push the wrapper for statedb.GetBalance
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		pushBigInt(dw.db.GetBalance(common.BytesToAddress(popSlice(ctx))), ctx)
		return 1
	})
	dc.PutPropString(obj, "getBalance")

	// Push the wrapper for statedb.GetNonce
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		ctx.PushInt(int(dw.db.GetNonce(common.BytesToAddress(popSlice(ctx)))))
		return 1
	})
	dc.PutPropString(obj, "getNonce")

	// Push the wrapper for statedb.GetCode
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		code := dw.db.GetCode(common.BytesToAddress(popSlice(ctx)))

		ptr := ctx.PushFixedBuffer(len(code))
		copy(makeSlice(ptr, uint(len(code))), code)
		return 1
	})
	dc.PutPropString(obj, "getCode")

	// Push the wrapper for statedb.GetState
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		hash := popSlice(ctx)
		addr := popSlice(ctx)

		state := dw.db.GetState(common.BytesToAddress(addr), common.BytesToHash(hash))

		ptr := ctx.PushFixedBuffer(len(state))
		copy(makeSlice(ptr, uint(len(state))), state[:])
		return 1
	})
	dc.PutPropString(obj, "getState")

	// Push the wrapper for statedb.Exists
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		ctx.PushBoolean(dw.db.Exist(common.BytesToAddress(popSlice(ctx))))
		return 1
	})
	dc.PutPropString(obj, "exists")
}

// contractWrapper provides a JavaScript wrapper around vm.Contract
type contractWrapper2 struct {
	contract *vm.Contract
}

// pushObject assembles a JSVM object wrapping a swappable contract and pushes it
// onto the VM stack.
func (cw *contractWrapper2) pushObject(dc *duktape.Context) {
	obj := dc.PushObject()

	// Push the wrapper for contract.Caller
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		ptr := ctx.PushFixedBuffer(20)
		copy(makeSlice(ptr, 20), cw.contract.Caller().Bytes())
		return 1
	})
	dc.PutPropString(obj, "getCaller")

	// Push the wrapper for contract.Address
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		ptr := ctx.PushFixedBuffer(20)
		copy(makeSlice(ptr, 20), cw.contract.Address().Bytes())
		return 1
	})
	dc.PutPropString(obj, "getAddress")

	// Push the wrapper for contract.Value
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		pushBigInt(cw.contract.Value(), ctx)
		return 1
	})
	dc.PutPropString(obj, "getValue")

	// Push the wrapper for contract.Input
	dc.PushGoFunction(func(ctx *duktape.Context) int {
		blob := cw.contract.Input

		ptr := ctx.PushFixedBuffer(len(blob))
		copy(makeSlice(ptr, uint(len(blob))), blob)
		return 1
	})
	dc.PutPropString(obj, "getInput")
}

// Tracer provides an implementation of Tracer that evaluates a Javascript
// function for each VM execution step.
type JsTracer struct {
	inited bool    // Flag whether the context was already inited from the EVM
	env    *vm.EVM // EVM instance executing the code being traced

	vm *duktape.Context // Javascript VM instance

	tracerObject int // Stack index of the tracer JavaScript object
	stateObject  int // Stack index of the global state to pull arguments from

	opWrapper       *opWrapper2       // Wrapper around the VM opcode
	stackWrapper    *stackWrapper2    // Wrapper around the VM stack
	memoryWrapper   *memoryWrapper2   // Wrapper around the VM memory
	contractWrapper *contractWrapper2 // Wrapper around the contract object
	dbWrapper       *dbWrapper2       // Wrapper around the VM environment

	pcValue     *uint   // Swappable pc value wrapped by a log accessor
	gasValue    *uint   // Swappable gas value wrapped by a log accessor
	costValue   *uint   // Swappable cost value wrapped by a log accessor
	depthValue  *uint   // Swappable depth value wrapped by a log accessor
	errorValue  *string // Swappable error value wrapped by a log accessor
	refundValue *uint   // Swappable refund value wrapped by a log accessor

	ctx map[string]interface{} // Transaction context gathered throughout execution
	err error                  // Error, if one has occurred

	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption
}

// New instantiates a new tracer instance. code specifies a Javascript snippet,
// which must evaluate to an expression returning an object with 'step', 'fault'
// and 'result' functions.
func New2(code string) (*JsTracer, error) {
	// Resolve any tracers by name and assemble the tracer object
	if tracer, ok := tracer(code); ok {
		code = tracer
	}
	tracer := &JsTracer{
		vm:              duktape.New(),
		ctx:             make(map[string]interface{}),
		opWrapper:       new(opWrapper2),
		stackWrapper:    new(stackWrapper2),
		memoryWrapper:   new(memoryWrapper2),
		contractWrapper: new(contractWrapper2),
		dbWrapper:       new(dbWrapper2),
		pcValue:         new(uint),
		gasValue:        new(uint),
		costValue:       new(uint),
		depthValue:      new(uint),
		refundValue:     new(uint),
	}
	// Set up builtins for this environment
	tracer.vm.PushGlobalGoFunction("toHex", func(ctx *duktape.Context) int {
		ctx.PushString(hexutil.Encode(popSlice(ctx)))
		return 1
	})
	tracer.vm.PushGlobalGoFunction("toWord", func(ctx *duktape.Context) int {
		var word common.Hash
		if ptr, size := ctx.GetBuffer(-1); ptr != nil {
			word = common.BytesToHash(makeSlice(ptr, size))
		} else {
			word = common.HexToHash(ctx.GetString(-1))
		}
		ctx.Pop()
		copy(makeSlice(ctx.PushFixedBuffer(32), 32), word[:])
		return 1
	})
	tracer.vm.PushGlobalGoFunction("toAddress", func(ctx *duktape.Context) int {
		var addr common.Address
		if ptr, size := ctx.GetBuffer(-1); ptr != nil {
			addr = common.BytesToAddress(makeSlice(ptr, size))
		} else {
			addr = common.HexToAddress(ctx.GetString(-1))
		}
		ctx.Pop()
		copy(makeSlice(ctx.PushFixedBuffer(20), 20), addr[:])
		return 1
	})
	tracer.vm.PushGlobalGoFunction("toContract", func(ctx *duktape.Context) int {
		var from common.Address
		if ptr, size := ctx.GetBuffer(-2); ptr != nil {
			from = common.BytesToAddress(makeSlice(ptr, size))
		} else {
			from = common.HexToAddress(ctx.GetString(-2))
		}
		nonce := uint64(ctx.GetInt(-1))
		ctx.Pop2()

		contract := crypto.CreateAddress(from, nonce)
		copy(makeSlice(ctx.PushFixedBuffer(20), 20), contract[:])
		return 1
	})
	tracer.vm.PushGlobalGoFunction("toContract2", func(ctx *duktape.Context) int {
		var from common.Address
		if ptr, size := ctx.GetBuffer(-3); ptr != nil {
			from = common.BytesToAddress(makeSlice(ptr, size))
		} else {
			from = common.HexToAddress(ctx.GetString(-3))
		}
		// Retrieve salt hex string from js stack
		salt := common.HexToHash(ctx.GetString(-2))
		// Retrieve code slice from js stack
		var code []byte
		if ptr, size := ctx.GetBuffer(-1); ptr != nil {
			code = common.CopyBytes(makeSlice(ptr, size))
		} else {
			code = common.FromHex(ctx.GetString(-1))
		}
		codeHash := crypto.Keccak256(code)
		ctx.Pop3()
		contract := crypto.CreateAddress2(from, salt, codeHash)
		copy(makeSlice(ctx.PushFixedBuffer(20), 20), contract[:])
		return 1
	})
	tracer.vm.PushGlobalGoFunction("isPrecompiled", func(ctx *duktape.Context) int {
		_, ok := vm.PrecompiledContractsByzantium[common.BytesToAddress(popSlice(ctx))]
		ctx.PushBoolean(ok)
		return 1
	})
	tracer.vm.PushGlobalGoFunction("slice", func(ctx *duktape.Context) int {
		start, end := ctx.GetInt(-2), ctx.GetInt(-1)
		ctx.Pop2()

		blob := popSlice(ctx)
		size := end - start

		if start < 0 || start > end || end > len(blob) {
			// TODO(karalabe): We can't js-throw from Go inside duktape inside Go. The Go
			// runtime goes belly up https://github.com/golang/go/issues/15639.
			log.Warn("Tracer accessed out of bound memory", "available", len(blob), "offset", start, "size", size)
			ctx.PushFixedBuffer(0)
			return 1
		}
		copy(makeSlice(ctx.PushFixedBuffer(size), uint(size)), blob[start:end])
		return 1
	})
	// Push the JavaScript tracer as object #0 onto the JSVM stack and validate it
	if err := tracer.vm.PevalString("(" + code + ")"); err != nil {
		log.Warn("Failed to compile tracer", "err", err)
		return nil, err
	}
	tracer.tracerObject = 0 // yeah, nice, eval can't return the index itself

	if !tracer.vm.GetPropString(tracer.tracerObject, "step") {
		return nil, fmt.Errorf("trace object must expose a function step()")
	}
	tracer.vm.Pop()

	if !tracer.vm.GetPropString(tracer.tracerObject, "fault") {
		return nil, fmt.Errorf("trace object must expose a function fault()")
	}
	tracer.vm.Pop()

	if !tracer.vm.GetPropString(tracer.tracerObject, "result") {
		return nil, fmt.Errorf("trace object must expose a function result()")
	}
	tracer.vm.Pop()

	// Tracer is valid, inject the big int library to access large numbers
	tracer.vm.EvalString(bigIntegerJS)
	tracer.vm.PutGlobalString("bigInt")

	// Push the global environment state as object #1 into the JSVM stack
	tracer.stateObject = tracer.vm.PushObject()

	logObject := tracer.vm.PushObject()

	tracer.opWrapper.pushObject(tracer.vm)
	tracer.vm.PutPropString(logObject, "op")

	tracer.stackWrapper.pushObject(tracer.vm)
	tracer.vm.PutPropString(logObject, "stack")

	tracer.memoryWrapper.pushObject(tracer.vm)
	tracer.vm.PutPropString(logObject, "memory")

	tracer.contractWrapper.pushObject(tracer.vm)
	tracer.vm.PutPropString(logObject, "contract")

	tracer.vm.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushUint(*tracer.pcValue); return 1 })
	tracer.vm.PutPropString(logObject, "getPC")

	tracer.vm.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushUint(*tracer.gasValue); return 1 })
	tracer.vm.PutPropString(logObject, "getGas")

	tracer.vm.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushUint(*tracer.costValue); return 1 })
	tracer.vm.PutPropString(logObject, "getCost")

	tracer.vm.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushUint(*tracer.depthValue); return 1 })
	tracer.vm.PutPropString(logObject, "getDepth")

	tracer.vm.PushGoFunction(func(ctx *duktape.Context) int { ctx.PushUint(*tracer.refundValue); return 1 })
	tracer.vm.PutPropString(logObject, "getRefund")

	tracer.vm.PushGoFunction(func(ctx *duktape.Context) int {
		if tracer.errorValue != nil {
			ctx.PushString(*tracer.errorValue)
		} else {
			ctx.PushUndefined()
		}
		return 1
	})
	tracer.vm.PutPropString(logObject, "getError")

	tracer.vm.PutPropString(tracer.stateObject, "log")

	tracer.dbWrapper.pushObject(tracer.vm)
	tracer.vm.PutPropString(tracer.stateObject, "db")

	return tracer, nil
}

// Stop terminates execution of the tracer at the first opportune moment.
func (jst *JsTracer) Stop(err error) {
	jst.reason = err
	atomic.StoreUint32(&jst.interrupt, 1)
}

// call executes a method on a JS object, catching any errors, formatting and
// returning them as error objects.
func (jst *JsTracer) call(method string, args ...string) (json.RawMessage, error) {
	// Execute the JavaScript call and return any error
	jst.vm.PushString(method)
	for _, arg := range args {
		jst.vm.GetPropString(jst.stateObject, arg)
	}
	code := jst.vm.PcallProp(jst.tracerObject, len(args))
	defer jst.vm.Pop()

	if code != 0 {
		err := jst.vm.SafeToString(-1)
		return nil, errors.New(err)
	}
	// No error occurred, extract return value and return
	return json.RawMessage(jst.vm.JsonEncode(-1)), nil
}

// CaptureStart implements the Tracer interface to initialize the tracing operation.
func (jst *JsTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	jst.ctx["type"] = "CALL"
	if create {
		jst.ctx["type"] = "CREATE"
	}
	jst.ctx["from"] = from
	jst.ctx["to"] = to
	jst.ctx["input"] = input
	jst.ctx["gas"] = gas
	jst.ctx["value"] = value
}

// CaptureState implements the Tracer interface to trace a single step of VM execution.
func (jst *JsTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if jst.err == nil {
		// Initialize the context if it wasn't done yet
		if !jst.inited {
			jst.ctx["block"] = jst.env.Context.BlockNumber.Uint64()
			jst.inited = true
		}
		// If tracing was interrupted, set the error and stop
		if atomic.LoadUint32(&jst.interrupt) > 0 {
			jst.err = jst.reason
			return
		}
		jst.opWrapper.op = op
		jst.stackWrapper.stack = scope.Stack
		jst.memoryWrapper.memory = scope.Memory
		jst.contractWrapper.contract = scope.Contract
		jst.dbWrapper.db = jst.env.StateDB

		*jst.pcValue = uint(pc)
		*jst.gasValue = uint(gas)
		*jst.costValue = uint(cost)
		*jst.depthValue = uint(depth)
		*jst.refundValue = uint(jst.env.StateDB.GetRefund())

		jst.errorValue = nil
		if err != nil {
			jst.errorValue = new(string)
			*jst.errorValue = err.Error()
		}
		_, err := jst.call("step", "log", "db")
		if err != nil {
			jst.err = wrapError("step", err)
		}
	}
	return
}

// CaptureFault implements the Tracer interface to trace an execution fault
// while running an opcode.
func (jst *JsTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	if jst.err == nil {
		// Apart from the error, everything matches the previous invocation
		jst.errorValue = new(string)
		*jst.errorValue = err.Error()

		_, err := jst.call("fault", "log", "db")
		if err != nil {
			jst.err = wrapError("fault", err)
		}
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (jst *JsTracer) CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error) {
	jst.ctx["output"] = output
	jst.ctx["gasUsed"] = gasUsed
	jst.ctx["time"] = t.String()

	if err != nil {
		jst.ctx["error"] = err.Error()
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (jst *JsTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if jst.err != nil {
		return
	}
	// If tracing was interrupted, set the error and stop
	if atomic.LoadUint32(&jst.interrupt) > 0 {
		jst.err = jst.reason
		return
	}

	if _, err := jst.call("enter", "enter", "frame"); err != nil {
		jst.err = wrapError("enter", err)
	}
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (jst *JsTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	// If tracing was interrupted, set the error and stop
	if atomic.LoadUint32(&jst.interrupt) > 0 {
		jst.err = jst.reason
		return
	}

	if _, err := jst.call("exit", "exit", "frameResult"); err != nil {
		jst.err = wrapError("exit", err)
	}
}

// GetResult calls the Javascript 'result' function and returns its value, or any accumulated error
func (jst *JsTracer) GetResult() (json.RawMessage, error) {
	// Transform the context into a JavaScript object and inject into the state
	obj := jst.vm.PushObject()

	for key, val := range jst.ctx {

		switch val := val.(type) {
		case uint64:
			jst.vm.PushUint(uint(val))

		case string:
			jst.vm.PushString(val)

		case []byte:
			ptr := jst.vm.PushFixedBuffer(len(val))
			copy(makeSlice(ptr, uint(len(val))), val)

		case common.Address:
			ptr := jst.vm.PushFixedBuffer(20)
			copy(makeSlice(ptr, 20), val[:])

		case *big.Int:
			pushBigInt(val, jst.vm)

		default:
			panic(fmt.Sprintf("unsupported type: %T", val))
		}
		jst.vm.PutPropString(obj, key)
	}
	jst.vm.PutPropString(jst.stateObject, "ctx")

	// Finalize the trace and return the results
	result, err := jst.call("result", "ctx", "db")
	if err != nil {
		jst.err = wrapError("result", err)
	}
	// Clean up the JavaScript environment
	jst.vm.DestroyHeap()
	jst.vm.Destroy()

	return result, jst.err
}
