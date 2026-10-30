package server

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestValidateTaskScheduleTimezones(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for _, zone := range []string{"Asia/Shanghai", "UTC", "America/New_York"} {
		at := now.Add(time.Hour).In(time.FixedZone("input", 8*3600))
		v := &db.TaskSchedule{Timezone: zone, Start: &db.ScheduleEvent{At: at}}
		if err := validateSchedule(v, now); err != nil {
			t.Fatal(err)
		}
		if !v.Start.At.Equal(now.Add(time.Hour)) || v.Start.At.Location() != time.UTC {
			t.Fatalf("instant shifted: %v", v.Start.At)
		}
	}
	for _, v := range []*db.TaskSchedule{
		{Timezone: "Local"}, {Timezone: "bad/zone"},
		{Timezone: "UTC", Start: &db.ScheduleEvent{At: now}},
		{Timezone: "UTC", Start: &db.ScheduleEvent{At: now.Add(2 * time.Hour)}, Stop: &db.ScheduleEvent{At: now.Add(time.Hour)}},
	} {
		if validateSchedule(v, now) == nil {
			t.Fatalf("accepted invalid schedule %+v", v)
		}
	}
}

func TestTaskScheduleLifecycle(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}
	s := newAdmissionTestServer(m, func(*Task) bool { return false })
	s.ctx = context.Background()
	now := time.Now().UTC()
	task, err := m.CreateTaskWithOptions("scheduled", "goal", db.TaskCreateOptions{Schedule: &db.TaskSchedule{Timezone: "Asia/Shanghai", Start: &db.ScheduleEvent{At: now.Add(-time.Second), State: "pending"}, Stop: &db.ScheduleEvent{At: now.Add(time.Hour), State: "pending"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{})
	if !task.lifecycleSnapshot().Paused {
		t.Fatal("scheduled task started immediately")
	}
	s.stepTaskSchedules(now)
	all, err := m.pg.TaskSchedules()
	if err != nil {
		t.Fatal(err)
	}
	if !task.lifecycleSnapshot().Queued {
		t.Fatal("scheduled start must honor admission queue")
	}
	if all[task.ID].Start.State != "executed" {
		t.Fatalf("not started: %+v", all[task.ID].Start)
	}
	if _, err := s.applyTaskControl(task, "pause"); err != nil {
		t.Fatal(err)
	}
	all, _ = m.pg.TaskSchedules()
	if all[task.ID].Stop.State != "cancelled" {
		t.Fatal("manual pause did not cancel stop")
	}
	// A scheduled stop removes a task that is still waiting in admission.
	if _, err := s.applyTaskControl(task, "resume"); err != nil {
		t.Fatal(err)
	}
	stopOnly := &db.TaskSchedule{Timezone: "UTC", Stop: &db.ScheduleEvent{At: now.Add(-time.Second), State: "pending"}}
	if err := m.pg.SaveTaskSchedule(task.ID, stopOnly); err != nil {
		t.Fatal(err)
	}
	s.stepTaskSchedules(now)
	state := task.lifecycleSnapshot()
	if !state.Paused || state.Queued {
		t.Fatal("scheduled stop did not remove queued task")
	}
	all, _ = m.pg.TaskSchedules()
	if all[task.ID].Stop.State != "executed" {
		t.Fatal("stop not marked executed")
	}
	// An overdue start never resumes work; an overdue stop persists pause.
	v := &db.TaskSchedule{Timezone: "UTC", Start: &db.ScheduleEvent{At: now.Add(-time.Hour), State: "pending"}, Stop: &db.ScheduleEvent{At: now.Add(-time.Minute), State: "pending"}}
	if err := m.pg.SaveTaskSchedule(task.ID, v); err != nil {
		t.Fatal(err)
	}
	if err := s.recoverTaskSchedules(); err != nil {
		t.Fatal(err)
	}
	all, _ = m.pg.TaskSchedules()
	if all[task.ID].Start.State != "expired" || all[task.ID].Stop.State != "executed" {
		t.Fatalf("bad recovery: %+v", all[task.ID])
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	loaded, err := m.pg.GetTask(id)
	if err != nil || !loaded.Paused {
		t.Fatalf("stop not persisted: %v", err)
	}
}

func TestTaskScheduleVersionAndExpiry(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	s := newAdmissionTestServer(m, nil)
	s.ctx = context.Background()
	task, err := m.CreateTaskWithOptions("expiry", "goal", db.TaskCreateOptions{Schedule: &db.TaskSchedule{Timezone: "UTC", Start: &db.ScheduleEvent{At: time.Now().Add(-2 * time.Minute), State: "pending"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{})
	s.stepTaskSchedules(time.Now())
	all, err := m.pg.TaskSchedules()
	if err != nil {
		t.Fatal(err)
	}
	if all[task.ID].Start.State != "expired" || !task.lifecycleSnapshot().Paused {
		t.Fatal("expired start resumed task")
	}
	req := httptest.NewRequest("PUT", "/api/tasks/"+task.ID+"/schedule", strings.NewReader(`{"revision":0,"timezone":"UTC"}`))
	req.SetPathValue("id", task.ID)
	rec := httptest.NewRecorder()
	s.taskSchedule(rec, req)
	if rec.Code != 409 {
		t.Fatalf("stale edit status=%d body=%s", rec.Code, rec.Body.String())
	}
}
