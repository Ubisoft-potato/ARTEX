package main

import (
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// defaultGoMemLimit is a soft cap on the Go heap. The service runs inside a
// 5 GB cgroup shared with npm/node/Chromium children; letting the collector
// grow without a ceiling was one half of the 2026-10-27 freeze (the other half
// was untracked MCP process trees). 2 GiB leaves room for the browser children
// while still letting GC reclaim aggressively if a compaction spikes.
const defaultGoMemLimit = int64(2) << 30

// applyGoMemLimit sets GOMEMLIMIT in-process. Override with ARTEX_GOMEMLIMIT
// (e.g. "3GiB"; "0" disables the cap).
func applyGoMemLimit() {
	limit := defaultGoMemLimit
	if v := strings.TrimSpace(os.Getenv("ARTEX_GOMEMLIMIT")); v != "" {
		limit = parseByteSize(v)
	}
	if limit <= 0 {
		log.Printf("[config] Go 内存软上限: 已禁用")
		return
	}
	debug.SetMemoryLimit(limit)
	log.Printf("[config] Go 内存软上限: %d MiB", limit>>20)
}

// parseByteSize accepts plain bytes or a KiB/MiB/GiB (or KB/MB/GB) suffix.
func parseByteSize(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	units := []struct {
		suffix string
		mult   int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"B", 1},
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSuffix(s, u.suffix)
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || n < 0 {
		return 0
	}
	return int64(n * float64(mult))
}
