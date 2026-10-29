package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/agent"
)

// Registration and closing share a lock; Wait can never race a new Add.
func (s *Server) startBackground(fn func()) bool {
	s.backgroundMu.Lock()
	defer s.backgroundMu.Unlock()
	if s.closing || s.ctx.Err() != nil {
		return false
	}
	s.backgroundWG.Add(1)
	go func() { defer s.backgroundWG.Done(); fn() }()
	return true
}

func waitGroupContext(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown cancels inference, then waits for final writes before stores close.
// On timeout the caller leaves stores open until process exit.
func (s *Server) Shutdown(ctx context.Context) error {
	s.backgroundMu.Lock()
	s.closing = true
	s.backgroundMu.Unlock()
	s.engine.deleteMu.Lock()
	s.engine.stopping.Store(true)
	s.engine.deleteMu.Unlock()
	if s.cancel != nil {
		s.cancel(agent.AbortShutdown)
	}
	for {
		busy := false
		s.engine.inflight.Range(func(_, v any) bool {
			if v != nil && atomic.LoadInt64(v.(*int64)) > 0 {
				busy = true
			}
			return true
		})
		s.chatMu.Lock()
		busy = busy || len(s.chatBusy) > 0
		s.chatMu.Unlock()
		s.queueMu.Lock()
		for _, n := range s.triggerActive {
			busy = busy || n > 0
		}
		s.queueMu.Unlock()
		if s.side != nil {
			s.side.mu.Lock()
			busy = busy || len(s.side.runs) > 0
			s.side.mu.Unlock()
		}
		if !busy {
			break
		}
		if sleepCtx(ctx, 20*time.Millisecond) {
			return fmt.Errorf("等待 Agent 状态保存: %w", ctx.Err())
		}
	}
	if err := waitGroupContext(ctx, &s.backgroundWG); err != nil {
		return err
	}
	if err := waitGroupContext(ctx, &s.archiveWG); err != nil {
		return err
	}
	s.engine.runtimeMu.Lock()
	runtimes := make([]*taskRuntime, 0, len(s.engine.runtimes))
	for _, rt := range s.engine.runtimes {
		runtimes = append(runtimes, rt)
		rt.cancel()
	}
	s.engine.runtimeMu.Unlock()
	for _, rt := range runtimes {
		if err := waitGroupContext(ctx, &rt.wg); err != nil {
			return err
		}
	}
	if s.side != nil {
		select {
		case <-s.side.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.flushSideSnapshots(ctx)
	}
	if s.m.enrich != nil {
		if err := s.m.enrich.CloseContext(ctx); err != nil {
			return err
		}
	}
	if err := s.flushLogs(ctx); err != nil {
		return err
	}
	return ctx.Err()
}
