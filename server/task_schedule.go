package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	_ "time/tzdata"

	"github.com/Autumn-27/artex/db"
)

func validateSchedule(v *db.TaskSchedule, now time.Time) error {
	if v.Timezone == "" || v.Timezone == "Local" {
		return fmt.Errorf("请选择明确的 IANA 时区")
	}
	if _, err := time.LoadLocation(v.Timezone); err != nil {
		return fmt.Errorf("无效时区")
	}
	for _, e := range []*db.ScheduleEvent{v.Start, v.Stop} {
		if e != nil {
			if !e.At.After(now) {
				return fmt.Errorf("预约时间必须晚于当前时间")
			}
			e.At = e.At.UTC()
			e.State = "pending"
			e.Result = ""
		}
	}
	if v.Start != nil && v.Stop != nil && !v.Stop.At.After(v.Start.At) {
		return fmt.Errorf("停止时间必须晚于启动时间")
	}
	return nil
}
func emptySchedule() *db.TaskSchedule { return &db.TaskSchedule{Timezone: "Asia/Shanghai"} }
func (s *Server) taskSchedule(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	s.scheduleMu.Lock()
	defer s.scheduleMu.Unlock()
	release, lockErr := s.m.pg.LockTaskSchedules(s.ctx)
	if lockErr != nil {
		writeErr(w, 500, lockErr.Error())
		return
	}
	defer release()
	all, err := s.m.pg.TaskSchedules()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	old := all[t.ID]
	if old == nil {
		old = emptySchedule()
	}
	if r.Method == "GET" {
		writeJSON(w, 200, old)
		return
	}
	var v db.TaskSchedule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&v); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if v.Revision != old.Revision {
		writeErr(w, 409, "预约已变更，请刷新后重试")
		return
	}
	if r.Method == "DELETE" {
		v = *old
		cancelSchedule(&v)
	} else {
		if isTerminalStatus(t.lifecycleSnapshot().Status) {
			writeErr(w, 400, "终态任务不能预约启停")
			return
		}
		if err := validateSchedule(&v, time.Now()); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	v.Revision = old.Revision + 1
	if err := s.m.pg.SaveTaskSchedule(t.ID, &v); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}
func cancelSchedule(v *db.TaskSchedule) {
	for _, e := range []*db.ScheduleEvent{v.Start, v.Stop} {
		if e != nil && e.State == "pending" {
			e.State = "cancelled"
			e.Result = "手动取消"
		}
	}
}

// Called before runtime restoration; overdue stops must never briefly resume.
func (s *Server) recoverTaskSchedules() error {
	if s.m.pg == nil {
		return nil
	}
	all, err := s.m.pg.TaskSchedules()
	if err != nil {
		return err
	}
	now := time.Now()
	for id, v := range all {
		changed := false
		if v.Start != nil && v.Start.State == "pending" && !v.Start.At.After(now) {
			v.Start.State = "expired"
			v.Start.Result = "服务离线期间错过启动，不补跑"
			changed = true
		}
		if v.Stop != nil && v.Stop.State == "pending" && !v.Stop.At.After(now) {
			// Persist pause before LoadExisting reconstructs the in-memory lifecycle.
			result, err := s.m.pg.Exec(`UPDATE tasks SET paused=true,queued=false,queued_at=NULL WHERE id=$1 AND status NOT IN ('done','failed','timeout')`, id)
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			v.Stop.State = "executed"
			v.Stop.Result = "重启时补执行暂停"
			if count == 0 {
				v.Stop.State = "skipped"
				v.Stop.Result = "任务已结束"
			}
			changed = true
		}
		if changed {
			v.Revision++
			if err := s.m.pg.SaveTaskSchedule(id, v); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Server) runTaskSchedules() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.stepTaskSchedules(time.Now())
		}
	}
}
func (s *Server) stepTaskSchedules(now time.Time) {
	s.scheduleMu.Lock()
	defer s.scheduleMu.Unlock()
	release, lockErr := s.m.pg.LockTaskSchedules(s.ctx)
	if lockErr != nil {
		log.Printf("[schedule] lock: %v", lockErr)
		return
	}
	defer release()
	all, err := s.m.pg.TaskSchedules()
	if err != nil {
		log.Printf("[schedule] %v", err)
		return
	}
	for id, v := range all {
		changed := false
		for i, e := range []*db.ScheduleEvent{v.Start, v.Stop} {
			if e == nil || e.State != "pending" || e.At.After(now) {
				continue
			}
			t, ok := s.m.Task(id)
			if !ok {
				continue
			}
			state := t.lifecycleSnapshot()
			switch {
			case isTerminalStatus(state.Status):
				e.State = "skipped"
				e.Result = "任务已结束"
			case i == 0 && (now.Sub(e.At) > time.Minute || (v.Stop != nil && !v.Stop.At.After(now))):
				e.State = "expired"
				e.Result = "错过启动时间，不补跑"
			case (i == 0 && !state.Paused) || (i == 1 && state.Paused):
				e.State = "skipped"
				e.Result = "任务已处于目标状态"
			default:
				action := "resume"
				if i == 1 {
					action = "pause"
				}
				result, err := s.applyTaskControlWithCause(t, action, nil)
				if err != nil {
					e.Result = err.Error()
					changed = true
					continue
				}
				e.State = "executed"
				e.Result = result.Status
			}
			changed = true
		}
		if changed {
			v.Revision++
			if err := s.m.pg.SaveTaskSchedule(id, v); err != nil {
				log.Printf("[schedule] save %s: %v", id, err)
			}
		}
	}
}
