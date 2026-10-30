package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// TaskSchedule stores absolute instants; Timezone is only the display/input zone.
type TaskSchedule struct {
	Revision int64          `json:"revision"`
	Timezone string         `json:"timezone"`
	Start    *ScheduleEvent `json:"start,omitempty"`
	Stop     *ScheduleEvent `json:"stop,omitempty"`
}
type ScheduleEvent struct {
	At     time.Time `json:"at"`
	State  string    `json:"state"`
	Result string    `json:"result,omitempty"`
}

func (d *DB) TaskSchedules() (map[string]*TaskSchedule, error) {
	rows, err := d.Query(`SELECT task_id::text, payload, start_at, stop_at FROM task_schedules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*TaskSchedule{}
	for rows.Next() {
		var id string
		var raw []byte
		var startAt, stopAt sql.NullTime
		if err := rows.Scan(&id, &raw, &startAt, &stopAt); err != nil {
			return nil, err
		}
		var v TaskSchedule
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		if v.Start != nil && startAt.Valid {
			v.Start.At = startAt.Time.UTC()
		}
		if v.Stop != nil && stopAt.Valid {
			v.Stop.At = stopAt.Time.UTC()
		}
		out[id] = &v
	}
	return out, rows.Err()
}
func (d *DB) SaveTaskSchedule(id string, v *TaskSchedule) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.Exec(`INSERT INTO task_schedules(task_id,payload,start_at,stop_at) VALUES($1,$2,$3,$4) ON CONFLICT(task_id) DO UPDATE SET payload=EXCLUDED.payload,start_at=EXCLUDED.start_at,stop_at=EXCLUDED.stop_at`, id, string(raw), v.StartTime(), v.StopTime())
	return err
}

// LockTaskSchedules serializes claims and edits across server instances. The
// session lock stays on a dedicated connection until the returned release runs.
func (d *DB) LockTaskSchedules(ctx context.Context) (func(), error) {
	conn, err := d.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(7337741027)`); err != nil {
		conn.Close()
		return nil, err
	}
	return func() {
		defer conn.Close()
		conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741027)`)
	}, nil
}

func (v *TaskSchedule) StartTime() *time.Time {
	if v.Start == nil {
		return nil
	}
	return &v.Start.At
}
func (v *TaskSchedule) StopTime() *time.Time {
	if v.Stop == nil {
		return nil
	}
	return &v.Stop.At
}
