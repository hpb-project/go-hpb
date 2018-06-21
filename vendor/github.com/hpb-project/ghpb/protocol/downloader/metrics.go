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

// Contains the metrics collected by the downloader.

package downloader

import (
	"github.com/hpb-project/ghpb/metrics"
)

var (
	headerInMeter      = metrics.NewMeter("hpb/downloader/headers/in")
	headerReqTimer     = metrics.NewTimer("hpb/downloader/headers/req")
	headerDropMeter    = metrics.NewMeter("hpb/downloader/headers/drop")
	headerTimeoutMeter = metrics.NewMeter("hpb/downloader/headers/timeout")

	bodyInMeter      = metrics.NewMeter("hpb/downloader/bodies/in")
	bodyReqTimer     = metrics.NewTimer("hpb/downloader/bodies/req")
	bodyDropMeter    = metrics.NewMeter("hpb/downloader/bodies/drop")
	bodyTimeoutMeter = metrics.NewMeter("hpb/downloader/bodies/timeout")

	receiptInMeter      = metrics.NewMeter("hpb/downloader/receipts/in")
	receiptReqTimer     = metrics.NewTimer("hpb/downloader/receipts/req")
	receiptDropMeter    = metrics.NewMeter("hpb/downloader/receipts/drop")
	receiptTimeoutMeter = metrics.NewMeter("hpb/downloader/receipts/timeout")

	stateInMeter   = metrics.NewMeter("hpb/downloader/states/in")
	stateDropMeter = metrics.NewMeter("hpb/downloader/states/drop")
)
