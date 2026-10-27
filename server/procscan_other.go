//go:build !linux

package server

import "time"

// The cgroup memory guard is Linux-only: it needs cgroup v2 and /proc.
// These stubs keep the server building on Windows/macOS while disabling the
// process-tree reaper (the MCP process-group cleanup in mcpstdio still works
// there).
func cgroupProcs() []int                          { return nil }
func readProcInfo(int) (procInfo, bool)           { return procInfo{}, false }
func killProcTrees([]procTree, time.Duration) int { return 0 }
