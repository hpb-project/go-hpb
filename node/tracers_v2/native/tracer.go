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

/*
Package native is a collection of tracers written in go.

In order to add a native tracer and have it compiled into the binary, a new
file needs to be added to this folder, containing an implementation of the
`eth.tracers.Tracer` interface.

Aside from implementing the tracer, it also needs to register itself, using the
`register` method -- and this needs to be done in the package initialization.

Example:

```golang
func init() {
	register("noopTracerNative", newNoopTracer)
}
```
*/
package native

import (
	"errors"

	tracers "github.com/hpb-project/go-hpb/node/tracers_v2"
)

// init registers itself this packages as a lookup for tracers.
func init() {
	tracers.RegisterLookup(false, lookup)
}

/*
ctors is a map of package-local tracer constructors.

We cannot be certain about the order of init-functions within a package,
The go spec (https://golang.org/ref/spec#Package_initialization) says

> To ensure reproducible initialization behavior, build systems
> are encouraged to present multiple files belonging to the same
> package in lexical file name order to a compiler.

Hence, we cannot make the map in init, but must make it upon first use.
*/
var ctors map[string]func() tracers.Tracer

// register is used by native tracers to register their presence.
func register(name string, ctor func() tracers.Tracer) {
	if ctors == nil {
		ctors = make(map[string]func() tracers.Tracer)
	}
	ctors[name] = ctor
}

// lookup returns a tracer, if one can be matched to the given name.
func lookup(name string, ctx *tracers.Context) (tracers.Tracer, error) {
	if ctors == nil {
		ctors = make(map[string]func() tracers.Tracer)
	}
	if ctor, ok := ctors[name]; ok {
		return ctor(), nil
	}
	return nil, errors.New("no tracer found")
}
