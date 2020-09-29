// Copyright 2020 The go-hpb Authors
// Modified based on go-ethereum, which Copyright (C) 2020 The go-ethereum Authors.
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

// +build amd64,blsadx

package bls12381

// enableADX is true if the ADX/BMI2 instruction set was requested for the BLS
// implementation. The system may still fall back to plain ASM if the necessary
// instructions are unavailable on the CPU.
const enableADX = true