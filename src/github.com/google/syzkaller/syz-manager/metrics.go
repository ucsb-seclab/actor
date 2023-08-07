package main

import (
	"math"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/pkg/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	avgGroupEventsCallsPerMinute = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "avg_group_events_calls",
		Help: "Average number of calls to group events() per minute",
	})

	numPendingGroups = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "num_pending_groups",
		Help: "Number of pending groups waiting to be merged",
	})
)

var startTime time.Time
var numGroupEventsCalls int = 0

func initMetrics() {
	if *flagPprof {
		log.Logf(0, "Memory profiling enabled")
		/* Ref: https://pkg.go.dev/runtime
		* golang CPU profiling is enabled by default.
		* MemProfileRate controls the fraction of memory allocations that are recorded and reported in the memory profile.
		* The profiler aims to sample an average of one allocation per MemProfileRate bytes allocated.
		* Setting memprofilerate=X environment variable will update the value of runtime.MemProfileRate.
		* When set to 0 memory profiling is disabled. */
		log.Logf(0, "MemProfileRate1: %v", runtime.MemProfileRate)
		defer profile.Start(profile.MemProfile).Stop()
		log.Logf(0, "MemProfileRate2: %v", runtime.MemProfileRate)
	}
	if *flagProm {
		log.Logf(0, "Prometheus metrics enabled")
		http.Handle("/metrics", promhttp.Handler())
		prometheus.MustRegister(numPendingGroups)
	}
}

func updateAvgGroupEventsCallsPerMinute() {
	numGroupEventsCalls++
	endTime := time.Now()
	avgGroupEventsCallsPerMinute.Set(math.Round((float64(numGroupEventsCalls) / (endTime.Sub(startTime).Minutes()))))
}
