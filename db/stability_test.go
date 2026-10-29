package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func stabilityDB(t *testing.T) *DB {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Skip("isolated PostgreSQL not configured")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func stabilityTask(t *testing.T, d *DB) *Task {
	t.Helper()
	task, err := d.CreateTask("stability fixture", "goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
	})
	return task
}

func TestStabilityTimeoutEventsFollowTransitions(t *testing.T) {
	d := stabilityDB(t)
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "stability-timeout", Enabled: true, OnTaskTimeout: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM trigger_jobs WHERE trigger_id=$1`, tr.ID); d.DeleteTrigger(tr.ID) })
	a, b := stabilityTask(t, d), stabilityTask(t, d)
	for _, id := range []int64{b.ID, a.ID} {
		if err := d.SetStatus(id, "timeout"); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM trigger_jobs WHERE trigger_id=$1`, tr.ID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("out-of-order timeouts: count=%d err=%v", n, err)
	}
	if err := d.SetStatus(a.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM trigger_jobs WHERE trigger_id=$1`, tr.ID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("duplicate timeout event count=%d err=%v", n, err)
	}
	if err := d.SetStatus(a.ID, "running"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetStatus(a.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM trigger_jobs WHERE trigger_id=$1`, tr.ID).Scan(&n); err != nil || n != 3 {
		t.Fatalf("revived timeout count=%d err=%v", n, err)
	}
}

func TestStabilityTriggerQueueRollsBackAndReusesConversation(t *testing.T) {
	d := stabilityDB(t)
	ctx := context.Background()
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "stability-create", Enabled: true, OnTaskCreate: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM trigger_jobs WHERE trigger_id=$1`, tr.ID); d.DeleteTrigger(tr.ID) })
	task := stabilityTask(t, d)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE tasks SET status='timeout' WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	var id int64
	var raw []byte
	if err := d.QueryRow(`SELECT id,payload FROM trigger_jobs WHERE trigger_id=$1`, tr.ID).Scan(&id, &raw); err != nil {
		t.Fatal(err)
	}
	p := TriggerPayload{AgentKey: tr.AgentKey, Title: "durable", Message: "one input"}
	c, err := d.PrepareTriggerRun(ctx, []int64{id}, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID) })
	if _, err := d.PrepareTriggerRun(ctx, []int64{id}, p); err == nil {
		t.Fatal("claimed twice")
	}
	if err := d.RecoverTriggerJobs(ctx); err != nil {
		t.Fatal(err)
	}
	again, err := d.PrepareTriggerRun(ctx, []int64{id}, p)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != c.ID {
		t.Fatal("recovery created a second conversation")
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM conversation_activities WHERE conversation_id=$1 AND kind='user'`, c.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate input: %d %v", n, err)
	}
	if err := d.FinishTriggerRun(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
}

func TestStabilityIntentReceiptRejectsOldExecution(t *testing.T) {
	d := stabilityDB(t)
	task := stabilityTask(t, d)
	store := d.Exploration(task.ExplorationID)
	ctx := context.Background()
	id, err := store.AddNode("intent", map[string]any{"summary": "receipt"}, 0, "open", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.StartIntentExecution(ctx, id, "open", "worker", "old"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := store.CommitIntentOutcome(ctx, id, "old", "done", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitIntentOutcome(ctx, id, "old", "done", ""); err != nil {
		t.Fatal("receipt not idempotent", err)
	}
	if err := store.SetIntentState(id, "open"); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.StartIntentExecution(ctx, id, "open", "worker", "new"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := store.CommitIntentOutcome(ctx, id, "old", "done", ""); !errors.Is(err, ErrIntentStateConflict) {
		t.Fatalf("old receipt accepted: %v", err)
	}
	if err := store.CommitIntentOutcome(ctx, id, "new", "blocked", IntentBlockedLLMQuota); err != nil {
		t.Fatal(err)
	}
}

func TestStabilityActivityAllocationWaitsForCommit(t *testing.T) {
	d := stabilityDB(t)
	task := stabilityTask(t, d)
	store := d.Exploration(task.ExplorationID)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(-$1::bigint)`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := store.AppendActivityContext(ctx, Activity{Kind: "text", Summary: "wait"}); err == nil {
		t.Fatal("writer bypassed uncommitted predecessor")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendActivity(Activity{Kind: "text", Summary: "after commit"}); err != nil {
		t.Fatal(err)
	}
}

func TestStabilityQueueCapacityAndExpiry(t *testing.T) {
	d := stabilityDB(t)
	ctx := context.Background()
	key := fmt.Sprintf("capacity-%d", time.Now().UnixNano())
	t.Cleanup(func() { d.Exec(`DELETE FROM trigger_jobs WHERE agent_key=$1`, key) })
	if _, err := d.Exec(`INSERT INTO trigger_jobs(event_key,agent_key,payload) SELECT $1||g::text,$1,'{}'::jsonb FROM generate_series(1,1001) g`, key); err != nil {
		t.Fatal(err)
	}
	var pending, rejected int
	if err := d.QueryRow(`SELECT count(*) FILTER(WHERE state='pending'),count(*) FILTER(WHERE state='rejected') FROM trigger_jobs WHERE agent_key=$1`, key).Scan(&pending, &rejected); err != nil {
		t.Fatal(err)
	}
	if pending > 1000 || rejected == 0 {
		t.Fatalf("unbounded queue: pending=%d rejected=%d", pending, rejected)
	}
	if _, err := d.Exec(`UPDATE trigger_jobs SET created_at=now()-interval '2 days' WHERE agent_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if err := d.MaintainTriggerJobs(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM trigger_jobs WHERE agent_key=$1 AND state='pending'`, key).Scan(&pending); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
}

func TestStabilityPoolWaitRespectsCancellation(t *testing.T) {
	d := stabilityDB(t)
	task := stabilityTask(t, d)
	d.SetMaxOpenConns(4)
	for n := 0; n < 4; n++ {
		conn, err := d.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.Exploration(task.ExplorationID).AppendActivityContext(ctx, Activity{Kind: "text"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool wait did not cancel: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("pool acquisition exceeded caller deadline")
	}
}

func TestStabilityArchiveRestoreDoesNotEmitEvents(t *testing.T) {
	d := stabilityDB(t)
	task := stabilityTask(t, d)
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "archive-event-check", Enabled: true, OnFinding: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM trigger_jobs WHERE trigger_id=$1`, tr.ID); d.DeleteTrigger(tr.ID) })
	node, err := d.Exploration(task.ExplorationID).AddNode("finding", map[string]any{"summary": "archived"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err := d.QueryRow(`SELECT json_agg(row_to_json(n)) FROM exploration_nodes n WHERE id=$1`, node).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var legacy []map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy[0], "execution_token")
	raw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT set_config('artex.restore_mode','on',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM exploration_nodes WHERE id=$1`, node); err != nil {
		t.Fatal(err)
	}
	if err := insertArchiveRows(tx, "exploration_nodes", raw); err != nil {
		t.Fatal("legacy archive restore failed", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM trigger_jobs WHERE trigger_id=$1`, tr.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("historical event was re-enqueued: %d %v", count, err)
	}
}
