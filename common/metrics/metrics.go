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

// Package metrics provides general system and process level metrics collection.
package metrics

import (
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/deathowl/go-metrics-prometheus"
	"github.com/hpb-project/go-hpb/common/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-metrics/exp"
	"net/http"
)

// MetricsEnabledFlag is the CLI flag name to use to enable metrics collections.
const MetricsEnabledFlag = "metrics"

// Enabled is the flag specifying if metrics are enable or not.
var Enabled = true

// Init enables or disables the metrics system. Since we need this to run before
// any other code gets to create meters and timers, we'll actually do an ugly hack
// and peek into the command line args for the metrics flag.
func Start() {
	for _, arg := range os.Args {
		if strings.TrimLeft(arg, "-") == MetricsEnabledFlag {
			log.Info("Enabling metrics collection")
			Enabled = true
		}
	}
	prometheusRegistry := prometheus.NewRegistry()
	prometheusRegistry.MustRegister(prometheus.NewProcessCollector(os.Getpid(), ""))
	prometheusRegistry.MustRegister(prometheus.NewGoCollector())
	metricsRegistry := metrics.DefaultRegistry
	pClient := prometheusmetrics.NewPrometheusProvider(metricsRegistry, "go_hpb", "", prometheusRegistry, 1*time.Second)
	go pClient.UpdatePrometheusMetrics()
	exp.Exp(metricsRegistry)
	go func() {
		http.Handle("/metrics", promhttp.InstrumentMetricHandler(
			prometheusRegistry, promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}),
		))
		http.ListenAndServe("0.0.0.0:8080", nil)
	}()
}

// NewCounter create a new metrics Counter, either a real one of a NOP stub depending
// on the metrics flag.
func NewCounter(name string) metrics.Counter {
	if !Enabled {
		return new(metrics.NilCounter)
	}
	return metrics.GetOrRegisterCounter(strings.NewReplacer("/", "_").Replace(name), metrics.DefaultRegistry)
}

// NewMeter create a new metrics Meter, either a real one of a NOP stub depending
// on the metrics flag.
func NewMeter(name string) metrics.Meter {
	if !Enabled {
		return new(metrics.NilMeter)
	}
	return metrics.GetOrRegisterMeter(strings.NewReplacer("/", "_").Replace(name), metrics.DefaultRegistry)
}

// NewTimer create a new metrics Timer, either a real one of a NOP stub depending
// on the metrics flag.
func NewTimer(name string) metrics.Timer {
	if !Enabled {
		return new(metrics.NilTimer)
	}
	return metrics.GetOrRegisterTimer(strings.NewReplacer("/", "_").Replace(name), metrics.DefaultRegistry)
}

// CollectProcessMetrics periodically collects various metrics about the running
// process.
func CollectProcessMetrics(refresh time.Duration) {
	// Short circuit if the metrics system is disabled
	if !Enabled {
		return
	}
	// Create the various data collectors
	memstats := make([]*runtime.MemStats, 2)
	diskstats := make([]*DiskStats, 2)
	for i := 0; i < len(memstats); i++ {
		memstats[i] = new(runtime.MemStats)
		diskstats[i] = new(DiskStats)
	}
	// Define the various metrics to collect
	memAllocs := NewMeter("system/memory/allocs")
	memFrees := NewMeter("system/memory/frees")
	memInuse := NewMeter("system/memory/inuse")
	memPauses := NewMeter("system/memory/pauses")

	var diskReads, diskReadBytes, diskWrites, diskWriteBytes metrics.Meter
	if err := ReadDiskStats(diskstats[0]); err == nil {
		diskReads = NewMeter("system/disk/readcount")
		diskReadBytes = NewMeter("system/disk/readdata")
		diskWrites = NewMeter("system/disk/writecount")
		diskWriteBytes = NewMeter("system/disk/writedata")
	} else {
		log.Debug("Failed to read disk metrics", "err", err)
	}
	// Iterate loading the different stats and updating the meters
	for i := 1; ; i++ {
		runtime.ReadMemStats(memstats[i%2])
		memAllocs.Mark(int64(memstats[i%2].Mallocs - memstats[(i-1)%2].Mallocs))
		memFrees.Mark(int64(memstats[i%2].Frees - memstats[(i-1)%2].Frees))
		memInuse.Mark(int64(memstats[i%2].Alloc - memstats[(i-1)%2].Alloc))
		memPauses.Mark(int64(memstats[i%2].PauseTotalNs - memstats[(i-1)%2].PauseTotalNs))

		if ReadDiskStats(diskstats[i%2]) == nil {
			diskReads.Mark(int64(diskstats[i%2].ReadCount - diskstats[(i-1)%2].ReadCount))
			diskReadBytes.Mark(int64(diskstats[i%2].ReadBytes - diskstats[(i-1)%2].ReadBytes))
			diskWrites.Mark(int64(diskstats[i%2].WriteCount - diskstats[(i-1)%2].WriteCount))
			diskWriteBytes.Mark(int64(diskstats[i%2].WriteBytes - diskstats[(i-1)%2].WriteBytes))
		}
		time.Sleep(refresh)
	}
}
