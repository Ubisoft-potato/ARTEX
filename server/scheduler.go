package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Source events are enqueued transactionally by PostgreSQL. This worker only
// schedules intervals, maintains queue bounds and resumes durable deliveries.
type Scheduler struct {
	s    *Server
	pg   *db.DB
	tick time.Duration
}

func newScheduler(s *Server) *Scheduler { return &Scheduler{s: s, pg: s.m.pg, tick: 5 * time.Second} }

func (sc *Scheduler) Run(ctx context.Context) {
	if sc.pg == nil {
		return
	}
	if err := retrySettlement(ctx, sc.pg.RecoverTriggerJobs); err != nil {
		log.Printf("[trigger] 恢复队列失败: %v", err)
		return
	}
	sc.step()
	ticker := time.NewTicker(sc.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.s.reconcileConcurrency()
			sc.step()
		}
	}
}

func (sc *Scheduler) step() {
	if err := sc.pg.QueueDueTriggers(sc.s.ctx); err != nil {
		log.Printf("[trigger] 定时触发入队: %v", err)
	}
	if err := sc.pg.MaintainTriggerJobs(sc.s.ctx, 24*time.Hour); err != nil {
		log.Printf("[trigger] 队列维护: %v", err)
	}
	sc.s.loadTriggerQueue()
}

// trunc caps s to max runes, appending an ellipsis + original length when cut.
func trunc(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + fmt.Sprintf("…(已截断,共 %d 字)", len(r))
}
