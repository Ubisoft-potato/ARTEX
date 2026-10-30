package db

import (
	"strconv"
	"testing"
	"time"
)

func TestTaskSchedulePersistenceAndDeletion(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	at := time.Date(2026, 11, 1, 0, 30, 0, 0, time.FixedZone("Shanghai", 8*3600))
	v := &TaskSchedule{Timezone: "Asia/Shanghai", Start: &ScheduleEvent{At: at, State: "pending"}}
	task, err := d.CreateTaskWithOptions("schedule durability", "goal", TaskCreateOptions{Schedule: v})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	id := strconv.FormatInt(task.ID, 10)
	all, err := d.TaskSchedules()
	if err != nil {
		t.Fatal(err)
	}
	if !all[id].Start.At.Equal(at) || all[id].Timezone != "Asia/Shanghai" {
		t.Fatalf("lost zone or shifted instant: %+v", all[id])
	}
	loaded, err := d.GetTask(task.ID)
	if err != nil || !loaded.Paused {
		t.Fatalf("not paused: %+v %v", loaded, err)
	}
	if err := d.DeleteTask(task.ID); err != nil {
		t.Fatal(err)
	}
	all, err = d.TaskSchedules()
	if err != nil {
		t.Fatal(err)
	}
	if all[id] != nil {
		t.Fatal("schedule survived task deletion")
	}
}
