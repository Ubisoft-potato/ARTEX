package server

import (
	"context"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
)

func triggerPayload(item triggeredRun) db.TriggerPayload {
	return db.TriggerPayload{AgentKey: item.agentKey, Title: item.title, Message: item.message,
		TaskID: item.taskID, TaskDesc: item.taskDesc, TaskGoal: item.taskGoal, Mergeable: item.mergeable}
}

func (s *Server) loadTriggerQueue() {
	if s.ctx.Err() != nil || s.m.pg == nil {
		return
	}
	jobs, err := s.m.pg.PendingTriggerJobs(s.ctx, 1000)
	if err != nil {
		log.Printf("[trigger] 加载队列: %v", err)
		return
	}
	configs := map[string]triggerBehavior{}
	available := map[string]bool{}
	for _, j := range jobs {
		if _, ok := configs[j.Payload.AgentKey]; !ok {
			configs[j.Payload.AgentKey] = s.readTriggerBehavior(j.Payload.AgentKey)
			available[j.Payload.AgentKey] = s.resolveChatAgent(&db.Conversation{AgentKey: j.Payload.AgentKey}) != nil
		}
	}
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.triggerLoaded == nil {
		s.triggerLoaded = map[int64]bool{}
	}
	for _, j := range jobs {
		if !available[j.Payload.AgentKey] {
			continue
		}
		if s.triggerLoaded[j.ID] {
			continue
		}
		p := j.Payload
		s.triggerLoaded[j.ID] = true
		s.triggerCfg[p.AgentKey] = configs[p.AgentKey]
		s.triggerQ[p.AgentKey] = append(s.triggerQ[p.AgentKey], triggeredRun{jobIDs: []int64{j.ID}, recovered: j.Recovery,
			agentKey: p.AgentKey, title: p.Title, message: p.Message, taskID: p.TaskID, taskDesc: p.TaskDesc, taskGoal: p.TaskGoal, mergeable: p.Mergeable})
	}
	for key := range s.triggerQ {
		s.pumpLocked(key)
	}
}

func (s *Server) finishTrigger(item triggeredRun, runErr error) {
	if len(item.jobIDs) == 0 {
		return
	}
	ctx := s.ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
	}
	if err := retrySettlement(ctx, func(c context.Context) error { return s.m.pg.FinishTriggerRun(c, item.jobIDs[0], runErr) }); err != nil {
		log.Printf("[trigger] 保存执行结果失败，保留队列恢复记录: %v", err)
	}
}

func mergedJobIDs(items []triggeredRun) []int64 {
	var ids []int64
	for _, item := range items {
		ids = append(ids, item.jobIDs...)
	}
	return ids
}
