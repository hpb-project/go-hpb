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

package hpbclient

import "github.com/hpb-project/go-hpb"

// Verify that Client implements the ethereum interfaces.
var (
	_ = hpb_project.ChainReader(&Client{})
	_ = hpb_project.TransactionReader(&Client{})
	_ = hpb_project.ChainStateReader(&Client{})
	_ = hpb_project.ChainSyncReader(&Client{})
	_ = hpb_project.ContractCaller(&Client{})
	_ = hpb_project.GasEstimator(&Client{})
	_ = hpb_project.GasPricer(&Client{})
	_ = hpb_project.LogFilterer(&Client{})
	_ = hpb_project.PendingStateReader(&Client{})
	// _ = ethereum.PendingStateEventer(&Client{})
	_ = hpb_project.PendingContractCaller(&Client{})
)
