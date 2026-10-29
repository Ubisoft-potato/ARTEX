package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/jackc/pgx/v5/pgconn"
)

// A receipt is fsynced before committing an execution's final state. Retrying
// this receipt never re-runs tools. Startup replays receipts BEFORE reclaiming
// running intents. Tokens prevent an old receipt from completing a newer run.
type settlementReceipt struct {
	TaskID        string `json:"task_id"`
	ExplorationID int64  `json:"exploration_id"`
	IntentID      int64  `json:"intent_id,omitempty"`
	Token         string `json:"token,omitempty"`
	State         string `json:"state"`
	BlockedReason string `json:"blocked_reason,omitempty"`
	FirstRunAt    int64  `json:"first_run_at,omitempty"`
	DeadlineAt    int64  `json:"deadline_at,omitempty"`
	RunRevision   int64  `json:"run_revision"`
	CreatedAt     int64  `json:"created_at"`
}

func writeSettlement(dir string, receipt settlementReceipt) (string, error) {
	if receipt.CreatedAt == 0 {
		receipt.CreatedAt = time.Now().UnixNano()
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := json.NewEncoder(f).Encode(receipt); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	path := f.Name() + ".json"
	if err := os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	d, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	return path, d.Sync()
}

// Cancellation stops backoff, but each final write gets a short independent
// context: cancelling a model must not cancel saving its outcome as well.
func retrySettlement(ctx context.Context, apply func(context.Context) error) error {
	delay := 100 * time.Millisecond
	for attempt := 0; ; attempt++ {
		writeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := apply(writeCtx)
		cancel()
		if err == nil || errors.Is(err, db.ErrIntentStateConflict) {
			return err
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code != "40001" && pgErr.Code != "40P01" && pgErr.Code != "55P03" && pgErr.Code != "57014" && pgErr.Code != "53300" && pgErr.Code != "57P01" && !strings.HasPrefix(pgErr.Code, "08") {
			return err // constraints/schema/programming errors require repair, not an endless retry
		}
		if attempt == 0 || attempt%10 == 0 {
			log.Printf("[settlement] 状态提交失败，将仅重试落库: %v", err)
		}
		if sleepCtx(ctx, delay) {
			return errors.Join(err, ctx.Err())
		}
		if delay < 5*time.Second {
			delay = min(delay*2, 5*time.Second)
		}
	}
}

func (e *Engine) applySettlement(ctx context.Context, t *Task, r settlementReceipt) error {
	if r.IntentID != 0 {
		return t.Store.CommitIntentOutcome(ctx, r.IntentID, r.Token, r.State, r.BlockedReason)
	}
	e.m.taskStateMu.Lock()
	defer e.m.taskStateMu.Unlock()
	id, err := strconv.ParseInt(r.TaskID, 10, 64)
	if err != nil {
		return err
	}
	res, err := e.m.pg.ExecContext(ctx, `UPDATE tasks SET status=$2,
 completed_at=COALESCE(completed_at,now()) WHERE id=$1 AND deleted_at IS NULL
 AND status NOT IN ('done','failed','timeout')
 AND COALESCE(FLOOR(EXTRACT(EPOCH FROM first_run_at))::bigint,0)=$3
 AND COALESCE(FLOOR(EXTRACT(EPOCH FROM deadline_at))::bigint,0)=$4 AND run_revision=$5`, id, r.State, r.FirstRunAt, r.DeadlineAt, r.RunRevision)
	if err != nil {
		return err
	}
	changed, _ := res.RowsAffected()
	var status string
	var completed sql.NullTime
	err = e.m.pg.QueryRowContext(ctx, `SELECT status,completed_at FROM tasks WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&status, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if changed == 0 && !isTerminalStatus(status) {
		return db.ErrIntentStateConflict
	}
	t.updateLifecycle(func(s *taskLifecycleState) {
		s.Status = status
		if completed.Valid {
			s.CompletedAt = completed.Time.Unix()
		}
	})
	return nil
}

func (e *Engine) commitSettlement(ctx context.Context, t *Task, r settlementReceipt) error {
	path, err := writeSettlement(filepath.Join(e.m.dir, ".settlements", t.ID), r)
	if err != nil {
		e.Pause(t.ID, nil)
		return fmt.Errorf("无法保存收尾凭据，任务已停止派工: %w", err)
	}
	err = retrySettlement(ctx, func(writeCtx context.Context) error { return e.applySettlement(writeCtx, t, r) })
	if err == nil || errors.Is(err, db.ErrIntentStateConflict) {
		if removeErr := os.Remove(path); removeErr != nil {
			return errors.Join(err, removeErr)
		}
	}
	return err
}

func (e *Engine) commitTaskTerminal(ctx context.Context, t *Task, status string) error {
	s := t.lifecycleSnapshot()
	return e.commitSettlement(ctx, t, settlementReceipt{TaskID: t.ID, ExplorationID: t.ExpID,
		State: status, FirstRunAt: s.FirstRunAt, DeadlineAt: s.DeadlineAt, RunRevision: s.RunRevision})
}

func (e *Engine) commitIntent(ctx context.Context, t *Task, intent *db.Node, state, reason string) error {
	return e.commitSettlement(ctx, t, settlementReceipt{TaskID: t.ID, ExplorationID: t.ExpID,
		IntentID: intent.ID, Token: intent.ExecutionToken, State: state, BlockedReason: reason})
}

func (e *Engine) recoverSettlements(ctx context.Context, t *Task) error {
	paths, err := filepath.Glob(filepath.Join(e.m.dir, ".settlements", t.ID, "*.json"))
	if err != nil {
		return err
	}
	type pending struct {
		path    string
		receipt settlementReceipt
	}
	var items []pending
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		var r settlementReceipt
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("读取收尾凭据 %s: %w", path, err)
		}
		if r.TaskID != t.ID || r.ExplorationID != t.ExpID {
			continue
		}
		items = append(items, pending{path, r})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].receipt.CreatedAt < items[j].receipt.CreatedAt })
	for _, item := range items {
		path, r := item.path, item.receipt
		if err := retrySettlement(ctx, func(c context.Context) error { return e.applySettlement(c, t, r) }); err != nil && !errors.Is(err, db.ErrIntentStateConflict) {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
