package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type TriggerPayload struct {
	AgentKey  string `json:"agent_key"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	TaskID    int64  `json:"task_id"`
	TaskDesc  string `json:"task_desc"`
	TaskGoal  string `json:"task_goal"`
	Mergeable bool   `json:"mergeable"`
}
type TriggerJob struct {
	ID       int64
	Payload  TriggerPayload
	Recovery bool
}

func (d *DB) EnqueueTriggerJob(ctx context.Context, key string, p TriggerPayload) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `INSERT INTO trigger_jobs(event_key,agent_key,payload) VALUES($1,$2,$3) ON CONFLICT(trigger_id,event_key) DO NOTHING`, key, p.AgentKey, b)
	return err
}

func (d *DB) QueueDueTriggers(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `WITH due AS (
 UPDATE agent_triggers SET last_fire=now() WHERE enabled AND interval_sec>0
 AND (last_fire IS NULL OR last_fire<=now()-make_interval(secs=>interval_sec))
 RETURNING *)
 INSERT INTO trigger_jobs(trigger_id,event_key,agent_key,payload)
 SELECT id,'interval:'||last_fire::text,agent_key,jsonb_build_object('agent_key',agent_key,
 'title','定时触发','message',interval_message||E'\n\n【本次为定时触发】'||last_fire::text,'mergeable',false)
 FROM due ON CONFLICT(trigger_id,event_key) DO NOTHING`)
	return err
}

func (d *DB) PendingTriggerJobs(ctx context.Context, limit int) ([]TriggerJob, error) {
	ctx, cancel := BoundedContext(ctx)
	defer cancel()
	rows, err := d.QueryContext(ctx, `SELECT id,payload,conversation_id IS NOT NULL FROM trigger_jobs WHERE state='pending' AND available_at<=now() ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TriggerJob
	for rows.Next() {
		var j TriggerJob
		var raw []byte
		if err := rows.Scan(&j.ID, &raw, &j.Recovery); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &j.Payload); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Conversation creation, input, group membership and queue claim commit together.
// On recovery the canonical job keeps its original conversation and merged input.
func (d *DB) PrepareTriggerRun(ctx context.Context, ids []int64, p TriggerPayload) (*Conversation, error) {
	ctx, cancel := BoundedContext(ctx)
	defer cancel()
	if len(ids) == 0 {
		return nil, fmt.Errorf("empty trigger job group")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,conversation_id FROM trigger_jobs WHERE id=ANY($1) AND state='pending' ORDER BY id FOR UPDATE`, ids)
	if err != nil {
		return nil, err
	}
	count := 0
	var cid sql.NullInt64
	for rows.Next() {
		var id int64
		var c sql.NullInt64
		if err := rows.Scan(&id, &c); err != nil {
			rows.Close()
			return nil, err
		}
		count++
		if c.Valid {
			cid = c
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count != len(ids) {
		return nil, fmt.Errorf("trigger jobs already claimed")
	}
	var c Conversation
	if cid.Valid {
		c, err = scanConv(tx.QueryRowContext(ctx, `SELECT `+convCols+` FROM conversations WHERE id=$1`, cid.Int64))
		if err != nil {
			return nil, err
		}
	} else {
		c, err = scanConv(tx.QueryRowContext(ctx, `INSERT INTO conversations(agent_key,title) VALUES($1,$2) RETURNING `+convCols, p.AgentKey, p.Title))
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO conversation_activities(conversation_id,worker,kind,summary,detail) VALUES($1,$2,'user',$3,$3)`, c.ID, p.AgentKey, p.Message)
		if err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE trigger_jobs SET state=CASE WHEN id=$2 THEN 'running' ELSE 'merged' END,
 group_id=$2,conversation_id=$3,payload=CASE WHEN id=$2 THEN $4 ELSE payload END,
 attempts=attempts+1,updated_at=now() WHERE id=ANY($1)`, ids, ids[0], c.ID, b)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (d *DB) FinishTriggerRun(ctx context.Context, id int64, runErr error) error {
	state, message := "completed", ""
	if runErr != nil {
		state = "pending"
		message = runErr.Error()
	}
	_, err := d.ExecContext(ctx, `UPDATE trigger_jobs SET state=CASE WHEN id=$1 THEN
 CASE WHEN $2='pending' AND attempts>=5 THEN 'failed' ELSE $2 END
 ELSE CASE WHEN $2='completed' THEN 'completed' ELSE 'merged' END END,
 attempts=attempts+CASE WHEN conversation_id IS NULL THEN 1 ELSE 0 END,
 last_error=$3,updated_at=now(),available_at=now()+make_interval(secs=>LEAST(300,5*power(2,LEAST(attempts,6)))::integer)
 WHERE (id=$1 OR group_id=$1) AND state IN ('pending','running','merged')`, id, state, message)
	return err
}

func (d *DB) RecoverTriggerJobs(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `UPDATE trigger_jobs SET state='pending',available_at=now(),last_error='服务重启，恢复原会话',updated_at=now() WHERE state='running'`)
	return err
}

// Explicit retention and expiry leave an auditable outcome, not a silent drop.
func (d *DB) MaintainTriggerJobs(ctx context.Context, maxAge time.Duration) error {
	_, err := d.ExecContext(ctx, `UPDATE trigger_jobs SET state='expired',last_error='排队超时',updated_at=now() WHERE state='pending' AND created_at<now()-make_interval(secs=>$1)`, maxAge.Seconds())
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `UPDATE trigger_jobs child SET state=parent.state,updated_at=now(),last_error=parent.last_error FROM trigger_jobs parent WHERE child.group_id=parent.id AND child.state='merged' AND parent.state IN ('failed','expired')`)
	if err != nil {
		return err
	}
	_, err = d.ExecContext(ctx, `DELETE FROM trigger_jobs WHERE state IN ('completed','failed','expired','rejected') AND updated_at<now()-interval '7 days'`)
	return err
}
